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

