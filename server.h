#pragma once

#include <sys/socket.h>
#include <netinet/in.h>

#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <stdbool.h>
#include <semaphore.h>

//aio
#include <aio.h>
#include <stddef.h>


struct client_t{
	int socketfd;
	bool handshake;
	struct sockaddr_in client_socket;
	struct aiocb aio_cb_read;
	size_t read_capacity;
	sem_t sem_read;
	struct aiocb aio_cb_write;
	size_t write_capacity;
	sem_t sem_write;
};

enum ESERVER{
	EWBUF = 1, //op with write buffer failed
	ERBUF,	// -//- read -//-
	SWBUF, //success op with write buffer
	SRBUF  // -//- read buffer
};

void async_dataframe_read_completition_handler(sigval_t sigval);
