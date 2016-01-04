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
int extract_key_from_valid_headers(char *headers, unsigned char *key);
int calculate_websocket_hash(const unsigned char *user_handshake, unsigned char *server_handshake);
