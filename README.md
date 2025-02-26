# RDMAPerfIssue
This is a minimal code to show a performance issur I have with RDMA send/recv

The way to compile is as follow :

To compile code :
make server [WRITE_SIZE=X]
make client [WRITE_SIZE=X]

To lunch the code :

./client <server_ip> <server_port> [Max_write_size]
