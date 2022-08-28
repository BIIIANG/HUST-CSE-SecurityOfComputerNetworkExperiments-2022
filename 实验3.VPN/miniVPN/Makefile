all: 
	gcc -o vpn_client vpn_client.c -lssl -lcrypto
	gcc -o vpn_server vpn_server.c -lssl -lcrypto -lcrypt -lpthread

clean: 
	rm -f vpn_client vpn_server 
	rm -f *~

