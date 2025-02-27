# RDMAPerfIssue
This is a minimal code to show a performance issue I have with RDMA send/recv
(client code contain a sleep AND writting to memory to prevent redudancy otpimisation that happen without)

The way to compile is as follow :

To compile code : (WRITE_SIZE is the max size (in bytes) of the memory region written)
make server [WRITE_SIZE=X]
make client [WRITE_SIZE=X]

To lunch the code :

sh -c 'echo 1 >/sys/devices/system/cpu/intel_pstate/no_turbo'

./client <server_ip> <server_port>
