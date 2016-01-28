#include "websocket.h"

static size_t bytes_to_number(unsigned char *buffer, size_t from, size_t to){
	//dirty hack
	size_t result = 0, i;
	for(i = from; i < to; i++){
		result = result << 8;
		result += buffer[i];
	}
	return result;
}
static int base64_encode(const unsigned char* buffer, size_t length, unsigned char* b64text) {
	BIO *bio, *b64;
	BUF_MEM *bufferPtr;

	b64 = BIO_new(BIO_f_base64());
	bio = BIO_new(BIO_s_mem());
	bio = BIO_push(b64, bio);

	BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL); 
	BIO_write(bio, buffer, length);
	BIO_flush(bio);
	BIO_get_mem_ptr(bio, &bufferPtr);
	BIO_set_close(bio, BIO_NOCLOSE);
	BIO_free_all(bio);
	memcpy(b64text, bufferPtr->data, strlen(bufferPtr->data));

	return 0;
}
/**
 * Returns:
 * 1 - invalid user_handshake
 * 0 - everything is ok
 */
int websocket_calculate_hash(const unsigned char *const user_handshake, unsigned char *server_handshake){
    unsigned char magic[] = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    size_t handshake_length = strlen(user_handshake);
    if(handshake_length != 24)
        return 1;
    size_t magic_length = strlen(magic);
	//sucks
    unsigned char *handshake = malloc(handshake_length + magic_length + 1);
    strcat(handshake, user_handshake);
    strcat(handshake, magic);

	unsigned char server_sha1[21] = {0};
    SHA1(handshake, handshake_length+magic_length, server_sha1);
	server_sha1[20] = 0;
	base64_encode(server_sha1, strlen(server_sha1), server_handshake);
    return 0;
}


/* RFC WebSocket DATAFRAME
	   0                   1                   2                   3
	  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
	 +-+-+-+-+-------+-+-------------+-------------------------------+
	 |F|R|R|R| opcode|M| Payload len |    Extended payload length    |
	 |I|S|S|S|  (4)  |A|     (7)     |             (16/64)           |
	 |N|V|V|V|       |S|             |   (if payload len==126/127)   |
	 | |1|2|3|       |K|             |                               |
	 +-+-+-+-+-------+-+-------------+ - - - - - - - - - - - - - - - +
	 |     Extended payload length continued, if payload len == 127  |
	 + - - - - - - - - - - - - - - - +-------------------------------+
	 |                               |Masking-key, if MASK set to 1  |
	 +-------------------------------+-------------------------------+
	 | Masking-key (continued)       |          Payload Data         |
	 +-------------------------------- - - - - - - - - - - - - - - - +
	 :                     Payload Data continued ...                :
	 + - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - +
	 |                     Payload Data continued ...                |
	 +---------------------------------------------------------------+
*/
struct websocket_message_t *websocket_decode_headers(void *ptr){
	unsigned char *buffer = ptr;
	struct websocket_message_t *message = malloc(sizeof(struct websocket_message_t));

	int8_t highter_bit_mask = 0x80;
	int8_t opcode_mask = 0x0F;
	int8_t payload_mask = 0x7F;

	unsigned char *mask = NULL;

	message->fin = (buffer[0] & highter_bit_mask) >> 7;
	message->opcode = buffer[0] & opcode_mask;
	message->is_masked = (bool)((buffer[1] & highter_bit_mask) >> 7);

	if(message->is_masked == 0){
		message->errcode = EWSMASKING;
		return message;
	}
	if(message->fin == 1 && message->opcode == 0){
		//not on my watch, scum!
		message->errcode = EWSFINCONT;
		return message;
	}

	size_t payload_length = buffer[1] & payload_mask;

	if(payload_length < 126){
		mask = buffer+2;		
		message->data_pointer = buffer+6;
	} else if(payload_length == 126){
		mask = buffer+4;
		payload_length = bytes_to_number(buffer, 2, 4);
		message->data_pointer = buffer+8;
	} else if(payload_length == 127){
		mask = buffer+10;
		payload_length = bytes_to_number(buffer, 2, 10);
		message->data_pointer = buffer+14;
	}

	message->length = payload_length;
	if(payload_length > 131072)
		message->errcode = EWSLONG;

	return message;
}

void websocket_unxor_message(char *data, char *mask, size_t length){
	for (size_t i = 0; i < length; i++) {
		data[i] = data[i] ^ mask[i % 4];
	}
}

char *websocket_encode_message(const struct websocket_message_t *message){
	size_t header_length = 2 + message->is_masked*4;
	size_t payload_length = message->length;
	size_t payload_length_save = payload_length;

	if(payload_length >= 65536){
		payload_length = 127;
		header_length += 8;
	} else if(payload_length < 65536 && payload_length > 125){
		payload_length = 126;
		header_length += 2; //16 bits for length
	}

	char *bytes = malloc(header_length + payload_length + 1);
	char *ptr = bytes;

	bytes[0] = (message->fin << 7) | message->opcode; //fin,rsrv + opcode
	bytes[1] = (message->is_masked << 7) | payload_length;
	ptr += 2;
	
	if(payload_length == 126){
		*ptr = *((size_t*)&payload_length_save);
		ptr += 2;
	} else if(payload_length == 127){
		*ptr = *((size_t*)&payload_length_save);
		ptr += 8;
	}

	if(message->is_masked == 1){
		//blablabla, gen mask and xor payload
		ptr += 4;
	}

	size_t i;
	for(i = 0; i < payload_length_save; i++){
		*(ptr+i) = (uint8_t)(message->data_pointer)[i];
	}

	return bytes;
}

struct websocket_message_t *websocket_message_processing(struct websocket_message_t *receive){
	struct websocket_message_t *answer = malloc(sizeof(struct websocket_message_t));

	answer->fin = 1;
	if(receive->opcode == OPPING){
		answer->opcode = OPPONG;
		answer->data_pointer = NULL;
	} else {
		answer->opcode = OPTEXT;
	}

	if(receive->is_masked == 1){
		char *data = malloc(receive->length);
		char mask[4] = {0};
		memcpy(data, receive->data_pointer, receive->length);
		memcpy(mask, receive->data_pointer-4, 4);
		websocket_unxor_message(data, mask, receive->length);
		answer->data_pointer = data;
	}
	answer->length = receive->length;

	return answer;
}
