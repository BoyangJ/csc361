.c.o:
	gcc -g -c -lpcap -lm $?

# compile packet parser program
all: tracer 

tracer: tracer.o util.o
	gcc -g -o tracer tracer.o util.o -lpcap -lm

