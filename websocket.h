#pragma once

#include <stdbool.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#include <openssl/sha.h>
//Encodes Base64
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>


/*websocket section*/

//errors
enum EWS{
	EWSMASKING = 1,
	EWSFINCONT,
	EWSLONG,
	EWSUNDEF
};


//opcodes
enum {
	OPCONT = 0,
	OPTEXT,
	OPBIN,
	OPCLOSE = 8,
	OPPING,
	OPPONG
};

struct websocket_message_t{
	enum EWS errcode;
	uint8_t fin;
	uint8_t opcode;
	bool is_masked;
	size_t length;
	char *data_pointer;
};


int32_t websocket_calculate_hash(const unsigned char *const user_handshake, unsigned char *server_handshake);
struct websocket_message_t * websocket_decode_headers(void *buffer);
struct websocket_message_t *websocket_unxor_message(struct websocket_message_t *message);
char * websocket_encode_message(const struct websocket_message_t *message);
