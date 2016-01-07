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

//errors
enum {
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
	int errcode;
	short fin;
	short opcode;
	short is_masked;
	char *data_pointer;
};


int websocket_calculate_hash(const unsigned char *user_handshake, unsigned char *server_handshake);
struct websocket_message_t websocket_decode_message(unsigned char *buffer);
char *websocket_encode_message(const struct websocket_message_t *message);
