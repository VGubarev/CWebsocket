#include "server.h"

#define MAX_CLIENTS 100
#define BUFFER_SIZE 4095


void async_read_completition_handler(sigval_t sigval){
	struct client_t *req;
	req = (struct client_t*)sigval.sival_ptr;
	ssize_t res;


	if (aio_error( &req->aio_cb_read ) == 0) {
		res = aio_return( &req->aio_cb_read );

		int sem_wait_result = sem_wait(&req->sem_read);
		if(sem_wait_result == 0){
			sem_post(&req->sem_read);
		}

		if(((char*)(req->aio_cb_read.aio_buf))[0] == 'G') { //then there are http request

			unsigned char key[25] = {0};
			unsigned char accepted_key[29] = {0};
			
			http_extract_key_from_valid_headers((char*)req->aio_cb_read.aio_buf, key);
			websocket_calculate_hash(key, accepted_key);

			char *http_answer_handshake = http_build_answer_handshake(accepted_key);
			strcpy((char*)req->aio_cb_write.aio_buf, http_answer_handshake);
			free(http_answer_handshake);


			sem_wait(&req->sem_write);
			aio_write(&req->aio_cb_write);
		} else {//or websocket dataframe
			((char*)(req->aio_cb_read.aio_buf))[res] = 0;

			struct websocket_message_t receive = websocket_decode_message((void*)req->aio_cb_read.aio_buf);

			receive.fin = 1;
			receive.opcode = OPTEXT;
			receive.is_masked = 0;

   			char *encoded = websocket_encode_message(&receive);
			strcpy((char*)req->aio_cb_write.aio_buf, encoded);
			free(encoded);


			sem_wait(&req->sem_write);
			aio_write(&req->aio_cb_write);
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
	if (aio_error( &req->aio_cb_write ) == 0){
		res = aio_return( &req->aio_cb_read );
		if(res > 0){
			sem_post(&req->sem_write);
		}
    }

    return;
}
int main(int argc, char *argv[])
{
    int32_t sockfd;
	int16_t portno = 2812;
	int8_t enable = 1;

	size_t client_offset = 0;
	ssize_t aio_read_ret;

	struct client_t *clients = calloc(1, sizeof(struct client_t)*MAX_CLIENTS);
    struct sockaddr_in serv_addr;
	int32_t clilen = sizeof(serv_addr);

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0)
		puts("Socked failed");

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = INADDR_ANY;
    serv_addr.sin_port = htons(portno);

	setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int));

    if (bind(sockfd, (struct sockaddr *) &serv_addr,
             sizeof(serv_addr)) < 0)
        puts("ERROR on binding");

    listen(sockfd,MAX_CLIENTS);
	while(client_offset < MAX_CLIENTS) {
		(clients[client_offset]).socketfd = accept(sockfd,
												   (struct sockaddr *) &((clients[client_offset]).client_socket),
												   (socklen_t *) &clilen);
		if ((clients[client_offset]).socketfd < 0) {
			puts("ERROR on accept");
			//continue;
		}

		//set up asyncrhonous structures for user
		//read
		int sem_read = sem_init(&clients[client_offset].sem_read, 0, 1);
		if(sem_read == -1) {
			puts("read semaphore cannot be initialized");
			return 1;
		}


		(clients[client_offset]).aio_cb_read = (struct aiocb){
			.aio_fildes = (clients[client_offset]).socketfd,
			.aio_buf = malloc(BUFFER_SIZE+1),
			.aio_nbytes = BUFFER_SIZE,
			.aio_offset = 0
		};

		(clients[client_offset]).aio_cb_read.aio_sigevent = (struct sigevent){
			.sigev_notify = SIGEV_THREAD,
			.sigev_notify_function = async_read_completition_handler,
			.sigev_notify_attributes = NULL,
			.sigev_value.sival_ptr = (void*)&clients[client_offset]
		};

		//write
		int sem_write = sem_init(&clients[client_offset].sem_write, 0, 1);
		if(sem_write == -1) {
			puts("write semaphore cannot be initialized");
			return 1;
		}


		(clients[client_offset]).aio_cb_write = (struct aiocb){
			.aio_fildes = (clients[client_offset]).socketfd,
			.aio_buf = malloc(BUFFER_SIZE+1),
			.aio_nbytes = BUFFER_SIZE,
			.aio_offset = 0
		};

		(clients[client_offset]).aio_cb_write.aio_sigevent = (struct sigevent){
			.sigev_notify = SIGEV_THREAD,
			.sigev_notify_function = async_write_completition_handler,
			.sigev_notify_attributes = NULL,
			.sigev_value.sival_ptr = (void*)&clients[client_offset]
		};


		aio_read_ret = aio_read(&(clients[client_offset]).aio_cb_read);
		if (aio_read_ret < 0) puts("fail");
		client_offset++;
	}
    return 0;
}
