# makefile for project 1 works both in linux and unix system now

.c.o:
	gcc -g -c $?

# compile client and server
all: SimpClient SimpServer

# compile client only 
SimpClient: SimpClient.o util.o
	gcc -g -o SimpClient SimpClient.o util.o  -lnsl

# compile server only
SimpServer: SimpServer.o util.o
	gcc -g -o SimpServer SimpServer.o util.o  -lnsl
