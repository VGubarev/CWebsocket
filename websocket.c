#include "server.h"
//Encodes Base64
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>
#include <stdint.h>

int base64_encode(const unsigned char* buffer, size_t length, unsigned char* b64text) { 
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
int calculate_websocket_hash(const unsigned char *user_handshake, unsigned char *server_handshake){
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
