# RDMAPerfIssue
This is a minimal code to show a performance issur I have with RDMA send/recv

The way to compile is as follow :

For the client:
make client

For the servers :

To compile the correct server code :
make server

To compile the code that take multiples seconds for a send/recv :
make server2

To lunch the code :

./server[2] <server_ip> <server_port>

./client <server_ip> <server_port> <seed> <rounds> [sleep]
