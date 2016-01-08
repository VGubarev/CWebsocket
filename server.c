#include "server.h"

#define MAX_CLIENTS 500
#define BUFFER_SIZE 4095


void async_read_completition_handler(sigval_t sigval){
	struct client_t *req;
	req = (struct client_t*)sigval.sival_ptr;
	ssize_t res;
	unsigned char key[25];
	memset(&key, 0, 25);
	unsigned char *accepted_key[29];
	memset(&accepted_key, 0, 29);


	if (aio_error( req ) == 0) {
		res = aio_return( &req->aio_cb_read );
		if(((char*)(req->aio_cb_read.aio_buf))[0] == 'G') { //then there are http request
			http_extract_key_from_valid_headers(req->aio_cb_read.aio_buf, key);
			websocket_calculate_hash(key, &accepted_key);

			char *http_answer_handshake = http_build_answer_handshake(&accepted_key);
			write(req->socketfd, http_answer_handshake, strlen(http_answer_handshake));
		} else {//or websocket dataframe
			((char*)(req->aio_cb_read.aio_buf))[res] = 0;
			struct websocket_message_t receive = websocket_decode_message(req->aio_cb_read.aio_buf);
			receive.fin = 1;
			receive.opcode = OPTEXT;
			receive.is_masked = 0;
   			char *encoded = websocket_encode_message(&receive);
			write(req->socketfd, encoded, strlen(encoded));
		}
		aio_read(&req->aio_cb_read);
    }
	
    return;
}

void async_write_completition_handler(sigval_t sigval){
	struct client_t *req;
	req = (struct client_t*)sigval.sival_ptr;
	ssize_t res;
	/* Did the request complete? */
	if (aio_error( req ) == 0) {
		res = aio_return( &req->aio_cb_read );
    }

    return;
}
int main(int argc, char *argv[])
{
    int sockfd, portno = 2812;
	int enable = 1;
	size_t client_offset = 0;
	ssize_t aio_read_ret;

	volatile struct client_t clients[MAX_CLIENTS];
    struct sockaddr_in serv_addr;
	int clilen = sizeof(serv_addr);

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

	memset(&clients, 0, sizeof(clients));

    listen(sockfd,MAX_CLIENTS);
	while(client_offset < MAX_CLIENTS) {
		(clients[client_offset]).socketfd = accept(sockfd,
												   (struct sockaddr *) &((clients[client_offset]).client_socket),
												   (socklen_t *) &clilen);
		if ((clients[client_offset]).socketfd < 0) {
			error("ERROR on accept");
			//continue;
		}

		//set up asyncrhonous structures for user
		(clients[client_offset]).aio_cb_read.aio_fildes = (clients[client_offset]).socketfd;
		(clients[client_offset]).aio_cb_read.aio_buf = malloc(BUFFER_SIZE+1);
		(clients[client_offset]).aio_cb_read.aio_nbytes = BUFFER_SIZE;
		(clients[client_offset]).aio_cb_read.aio_offset = 0;

		(clients[client_offset]).aio_cb_read.aio_sigevent.sigev_notify = SIGEV_THREAD;
		(clients[client_offset]).aio_cb_read.aio_sigevent.sigev_notify_function = async_read_completition_handler;
		(clients[client_offset]).aio_cb_read.aio_sigevent.sigev_notify_attributes = NULL;
		(clients[client_offset]).aio_cb_read.aio_sigevent.sigev_value.sival_ptr = &clients[client_offset];


		(clients[client_offset]).aio_cb_write.aio_fildes = (clients[client_offset]).socketfd;
		(clients[client_offset]).aio_cb_write.aio_buf = malloc(BUFFER_SIZE+1);
		(clients[client_offset]).aio_cb_write.aio_nbytes = BUFFER_SIZE;
		(clients[client_offset]).aio_cb_write.aio_offset = 0;

		(clients[client_offset]).aio_cb_write.aio_sigevent.sigev_notify = SIGEV_THREAD;
		(clients[client_offset]).aio_cb_write.aio_sigevent.sigev_notify_function = async_write_completition_handler;
		(clients[client_offset]).aio_cb_write.aio_sigevent.sigev_notify_attributes = NULL;
		(clients[client_offset]).aio_cb_write.aio_sigevent.sigev_value.sival_ptr = &clients[client_offset];


		aio_read_ret = aio_read(&(clients[client_offset]).aio_cb_read);
		if (aio_read_ret < 0) puts("fail");
		client_offset++;
	}
    return 0;
}