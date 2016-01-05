#include <openssl/sha.h>
#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <strings.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>


#define SHA_DIGEST_LEN 20

/*http section*/
int http_extract_key_from_valid_headers(char *headers, unsigned char *key);
char *http_build_answer_handshake(unsigned char *accepted_key);


/*websocket section*/

struct websocket_decode_t{
	int errcode;
	char *data_pointer;
};


int websocket_calculate_hash(const unsigned char *user_handshake, unsigned char *server_handshake);
size_t eight_bytes_to_number(unsigned char *buffer, size_t from, size_t to);
struct websocket_decode_t websocket_decode_message(unsigned char *buffer);
char *websocket_encode_message(char *payload);
