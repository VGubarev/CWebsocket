CFLAGS=-g -c -o
LFLAGS=-lssl -lcrypto -o

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
