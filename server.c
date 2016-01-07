#include "server.h"

void error(char *msg)
{
    perror(msg);
    exit(1);
}

int main(int argc, char *argv[])
{
    int sockfd, newsockfd, portno = 2812, clilen;
	int enable = 1;
    unsigned char buffer[4096];
    struct sockaddr_in serv_addr, cli_addr;
    int n;
	unsigned char key[25];

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0)
        error("ERROR opening socket");

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = INADDR_ANY;
    serv_addr.sin_port = htons(portno);

	setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int));

    if (bind(sockfd, (struct sockaddr *) &serv_addr,
             sizeof(serv_addr)) < 0)
        error("ERROR on binding");

    listen(sockfd,5);

    clilen = sizeof(cli_addr);

    newsockfd = accept(sockfd, (struct sockaddr *) &cli_addr, &clilen);

    if (newsockfd < 0)
        error("ERROR on accept");

    n = read(newsockfd,buffer,4095);
	buffer[n] = 0;

    if (n < 0) error("ERROR reading from socket");
	
	http_extract_key_from_valid_headers(buffer, key);
	//shit
	unsigned char *accepted_key = malloc(29);
	websocket_calculate_hash(key, accepted_key);	

	char *http_answer_handshake = http_build_answer_handshake(accepted_key);
    n = write(newsockfd,http_answer_handshake,strlen(http_answer_handshake));

    //if (n < 0) error("ERROR writing to socket");
	//now handshake ends and we can start exchange messages 
	//receive some websocket header + xor'ed bytes
   		n = read(newsockfd,buffer,4095);
   		buffer[n] = 0;
   		struct websocket_message_t receive = websocket_decode_message(buffer);
   		printf("Got: %s\n",receive.data_pointer);
		receive.fin = 1;
		receive.opcode = OPTEXT;
		receive.is_masked = 0;
   		char *encoded = websocket_encode_message(&receive);
   		n = write(newsockfd,encoded,strlen(encoded));
		char hello[] = "hello";
		receive.data_pointer = hello;
		receive.fin = 1;
		receive.opcode = OPTEXT;
		receive.is_masked = 0;
   		char *encoded2 = websocket_encode_message(&receive);
   		n = write(newsockfd,encoded2,strlen(encoded2));
    return 0;
}
