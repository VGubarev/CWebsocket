#include <openssl/sha.h>
#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <strings.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <semaphore.h>

//aio
#include <aio.h>
#include <stddef.h>


/*http section*/
bool http_extract_key_from_valid_headers(char *headers, unsigned char *key);
char * http_build_answer_handshake(unsigned char *accepted_key);


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
	int8_t fin;
	int8_t opcode;
	int8_t is_masked;
	char *data_pointer;
};

struct client_t{
	int socketfd;
	struct sockaddr_in client_socket;
	struct aiocb aio_cb_read;
	sem_t sem_read;
	struct aiocb aio_cb_write;
	sem_t sem_write;
	char *extended_read_buffer;
	char *extended_write_buffer;
};

int32_t websocket_calculate_hash(const unsigned char *const user_handshake, unsigned char *server_handshake);
struct websocket_message_t websocket_decode_message(void *buffer);
char *websocket_encode_message(const struct websocket_message_t *message);
