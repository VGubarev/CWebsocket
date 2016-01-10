CFLAGS=-g -march=native -Werror -Wshadow -c -std=c11 -o
LFLAGS=-pthread -lrt -lssl -lcrypto -o

server: server.o websocket.o http.o
	gcc ${LFLAGS} $@ $^
server.o: server.c
	gcc ${CFLAGS} $@ $<
websocket.o: websocket.c
	gcc ${CFLAGS} $@ $<
http.o: http.c
	gcc ${CFLAGS} $@ $<

clean:
	rm -rf *.o server
