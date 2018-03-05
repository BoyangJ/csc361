.c.o:
	gcc -g -c -lpcap $?

# compile packet parser program
all: packet 

packet: packet.o util.o
	gcc -g -o packet packet.o util.o -lpcap -lnsl


