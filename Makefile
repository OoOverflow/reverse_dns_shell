CC = gcc
CFLAGS = -O3 -Wall

all : dns_shell_server dns_shell_client
dns_shell_server : simple_dns_shell_server.c dns_packet_op.c base64.c exec_shell_cmd.c
	$(CC) $(CFLAGS) $^ -lpthread -o $@
dns_shell_client : simple_dns_shell_client.c dns_packet_op.c base64.c exec_shell_cmd.c
	$(CC) $(CFLAGS) $^ -o $@

clean:
	rm -rf dns_shell_server dns_shell_client

