CC=gcc
CFLAGS=-fPIC -O3 -march=native -D_GNU_SOURCE -g -w
LDFLAGS= -g -lpthread -lm -lrdmacm -libverbs -Wl,--unresolved-symbols=report-all



%.o: %.c
	$(CC) -o $@ -c $< $(CFLAGS)

client: lib_rdma.o common.o client.o
	$(CC) -o $@  $^ $(LDFLAGS)

server: server.o common.o lib_rdma.o
	$(CC) -o $@ $^ $(LDFLAGS)
	
client2: lib_rdma.o common.o client2.o
	$(CC) -o $@  $^ $(LDFLAGS)

server2: server2.o common.o lib_rdma.o
	$(CC) -o $@ $^ $(LDFLAGS)

clear:
	rm *.o server client
