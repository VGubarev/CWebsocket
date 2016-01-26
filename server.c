#include "server.h"
#include "websocket.h"
#include "http.h"

#define MAX_CLIENTS 100
#define BUFFER_SIZE 4095

int8_t handle_write_buffer(struct client_t* req, char *data_pointer){
	size_t answer_length;

	if ((answer_length = strlen(data_pointer)) <= req->write_capacity) {
		req->aio_cb_write.aio_nbytes = answer_length;
	} else {
		//then extend buffer
		char *ptr = realloc(&req->aio_cb_write.aio_buf, answer_length + 1);
		if (ptr != NULL) {
			req->write_capacity = answer_length;

			req->aio_cb_write.aio_buf = ptr;
			req->aio_cb_write.aio_nbytes = answer_length;
		} else {
			//TODO: alloc failed, handle disconnect
			return EWBUF;
		}
	}
	return SWBUF;
}

void async_headers_read_completition_handler(sigval_t sigval){
	struct client_t *req;
	req = (struct client_t*)sigval.sival_ptr;
	ssize_t res;
	char *data_pointer;

	if (aio_error( &req->aio_cb_read ) == 0) {
		res = aio_return( &req->aio_cb_read );

		sem_wait(&req->sem_read);

		 //then there are http request
		unsigned char key[25] = {0};
		unsigned char accepted_key[29] = {0};

		//TODO: wrong, dont cast to non-volatile, lock aio_buf, copy to non-volatile, unlock aio_buf
		bool is_headers_valid = http_extract_key_from_valid_headers((char*)req->aio_cb_read.aio_buf, key);


		if(is_headers_valid == false){
			//TODO: invalid headers, handle disconnect
			return;
		}

		//approve client connection
		req->handshake = true;

		websocket_calculate_hash(key, accepted_key);

		data_pointer = http_build_answer_handshake(accepted_key);

		if(data_pointer == NULL){
			//TODO: alloc failed, handle disconnect
			return;
		}
		//if it's ok, then we can be sure next packet will be websocket_message_t, so change handler to special function
		req->aio_cb_read.aio_sigevent.sigev_notify_function = async_dataframe_read_completition_handler;

		sem_wait(&req->sem_write);

		uint8_t status = handle_write_buffer(req, data_pointer);
		if(status != SWBUF){
			return;
		}

		memcpy((char*)req->aio_cb_write.aio_buf, data_pointer, strlen(data_pointer));
		free(data_pointer);

		//TODO: socket connection statement
		aio_write(&req->aio_cb_write);
	}
	//TODO: socket connection statement
	aio_read(&req->aio_cb_read);

    return;
}


void async_dataframe_read_completition_handler(sigval_t sigval){
	struct client_t *req;
	req = (struct client_t*)sigval.sival_ptr;
	ssize_t res;
	char *data_pointer;

	if (aio_error( &req->aio_cb_read ) == 0) {
		res = aio_return(&req->aio_cb_read);

		//TODO: ...
		((char *) (req->aio_cb_read.aio_buf))[res] = 0;

		//TODO: wrong, dont cast to non-volatile, lock aio_buf, copy to non-volatile, unlock aio_buf
		struct websocket_message_t *receive = websocket_decode_message((void *) req->aio_cb_read.aio_buf);
		receive = websocket_unxor_message(receive);
		//what the f..reak
		if(receive->errcode != OPCONT && receive->opcode != OPTEXT && receive->opcode != OPBIN &&
				receive->errcode != OPPING && receive->errcode != OPPONG && receive->errcode != OPCLOSE){
			//TODO: invalid message, handle disconnect
			return;
		}


		//TODO: handle long messages
		receive->fin = 1;
		if(receive->opcode == OPPING){
			receive->opcode = OPPONG;
			receive->data_pointer = NULL;
		} else {
			receive->opcode = OPTEXT;
		}
		receive->is_masked = 0;

		data_pointer = websocket_encode_message(receive);
		free(receive);

		sem_wait(&req->sem_write);
		uint8_t status = handle_write_buffer(req, data_pointer);
		if(status != SWBUF){
			return;
		}

		memcpy((char*)req->aio_cb_write.aio_buf, data_pointer, strlen(data_pointer));
		free(data_pointer);

		//TODO: socket connection statement
		aio_write(&req->aio_cb_write);
	}
	//TODO: socket connection statement
	aio_read(&req->aio_cb_read);

	return;
}

void async_write_completition_handler(sigval_t sigval){
	struct client_t *req;
	req = (struct client_t*)sigval.sival_ptr;
	ssize_t res;
	/* Did the request complete? */
	if (aio_error( &req->aio_cb_write ) == 0){
		res = aio_return( &req->aio_cb_write );

		sem_post(&req->sem_read);
		sem_post(&req->sem_write);
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

		(clients[client_offset]).read_capacity = BUFFER_SIZE;
		(clients[client_offset]).aio_cb_read = (struct aiocb){
			.aio_fildes = (clients[client_offset]).socketfd,
			.aio_buf = calloc(1, BUFFER_SIZE + 1),
			.aio_nbytes = BUFFER_SIZE,
			.aio_offset = 0
		};

		(clients[client_offset]).aio_cb_read.aio_sigevent = (struct sigevent){
			.sigev_notify = SIGEV_THREAD,
			.sigev_notify_function = async_headers_read_completition_handler,
			.sigev_notify_attributes = NULL,
			.sigev_value.sival_ptr = (void*)&clients[client_offset]
		};

		//write
		int sem_write = sem_init(&clients[client_offset].sem_write, 0, 1);
		if(sem_write == -1) {
			puts("write semaphore cannot be initialized");
			return 1;
		}


		(clients[client_offset]).write_capacity = BUFFER_SIZE;
		(clients[client_offset]).aio_cb_write = (struct aiocb){
			.aio_fildes = (clients[client_offset]).socketfd,
			.aio_buf = calloc(1, BUFFER_SIZE + 1),
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
