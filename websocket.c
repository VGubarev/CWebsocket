#include "server.h"
//Encodes Base64
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>
#include <stdint.h>

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
 * omg.. what da hell
 */
int websocket_calculate_hash(const unsigned char *user_handshake, unsigned char *server_handshake){
    unsigned char magic[] = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    size_t handshake_length = strlen(user_handshake);
    if(handshake_length != 24)
        return 1;
    size_t magic_length = strlen(magic);
	//sucks
    unsigned char *handshake = calloc(handshake_length + magic_length + 1, sizeof(char));
    strcat(handshake, user_handshake);
    strcat(handshake, magic);

	unsigned char server_sha1[21];
    SHA1(handshake, handshake_length+magic_length, server_sha1);
	base64_encode(server_sha1, strlen(server_sha1), server_handshake);
    return 0;
}



/*
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

/* message valid if: data xor'ed, fin = 1, rsv1-3 = 0, opcode = 1
   then function returns 0, else 1 in errcode in websocket_decode_t
   if valid, also data_pointer != NULL
*/
//worst parser ever..
struct websocket_decode_t websocket_decode_message(unsigned char *buffer){
	struct websocket_decode_t result;
	size_t payload_length, payload_offset = 0,mask_offset;
	//it's isy to check for valid. First byte must be eq 81
	if(buffer[0] != 0x81){
		result.errcode = 1;
		return result;
	} else {
		payload_offset++;
	}

	//then get length and mask
	int length_mask = 0x7F; 
	int mask_mask = 0x80; //lol
	if((buffer[1] & mask_mask) != mask_mask){
		//not masked
		result.errcode = 1;
		return result;
	}

	if((buffer[1] & length_mask) < 126){
		payload_length = (buffer[1] & length_mask);
		payload_offset++;
	} else if((buffer[1] & length_mask) == 126){
		payload_length = eight_bytes_to_number(buffer,2,3);		
		payload_offset+=2;
	} else if((buffer[1] & length_mask) == 127){
		payload_length = eight_bytes_to_number(buffer,2,9);		
		payload_offset+=8;
	}
	mask_offset = payload_offset;
	payload_offset+=4; //mask
	for(int i = 0; i < payload_length; i++){
		buffer[payload_offset+i] = buffer[payload_offset+i] ^ buffer[mask_offset + i%4];
	}

	result.errcode = 0;
	result.data_pointer=buffer+payload_offset;
	return result;
}

//dont forget clean malloc allocations
char *websocket_encode_message(char *payload){
	size_t payload_length = strlen(payload);
	char *message;
	size_t offset = 0;
	if(payload_length < 126){
		message = malloc(payload_length + 1 + 1);
		message[1] = payload_length;
		offset = 2;
	} else if(payload_length == 126){
		message = malloc(payload_length + 2 + 1);
		message[1] = (payload_length >> 8) & 0xFF;
		message[2] = payload_length & 0xFF;
		offset = 3;
	} else if(payload_length == 127){
		message = malloc(payload_length + 8 + 1);
		message[1] = (payload_length >> 56) & 0xFF;
		message[2] = (payload_length >> 48) & 0xFF;
		message[3] = (payload_length >> 40) & 0xFF;
		message[4] = (payload_length >> 32) & 0xFF;
		message[5] = (payload_length >> 24) & 0xFF;
		message[6] = (payload_length >> 16) & 0xFF;
		message[7] = (payload_length >> 8) & 0xFF;
		message[8] = payload_length & 0xFF;
		offset = 9;
	}
	message[0] = 0x81; //always it's final text frame
	for(int i = 0; i < payload_length; i++){
		message[offset+i] = payload[i];
	}
	return message;
}

//lyl, what the hell?
size_t eight_bytes_to_number(unsigned char *buffer, size_t from, size_t to){
	//dirty hack
	size_t result = *((size_t*)&buffer[from]);
	if(to - from == 2){
		result = result & 0xFF;
	} else if(to - from == 4){
		result = result & 0xFFFF;
	}
	return result;
}
