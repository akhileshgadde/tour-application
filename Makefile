CC = gcc

LIBS =  -lpthread\
	/users/cse533/Stevens/unpv13e/libunp.a

FLAGS =  -g -O2
CFLAGS = ${FLAGS} -I/users/cse533/Stevens/unpv13e/lib

all: tour arp

tour: tour.o get_hw_addrs.o
	${CC} ${FLAGS} -o tour tour.o get_hw_addrs.o ${LIBS}

tour.o : tour.c
	${CC} ${CFLAGS} -c tour.c

arp: arp.o get_hw_addrs.o
	${CC} ${FLAGS} -o arp arp.o get_hw_addrs.o ${LIBS}

arp.o : arp.c
	${CC} ${CFLAGS} -c arp.c

get_hw_addrs.o : get_hw_addrs.c
	${CC} ${CFLAGS} -c get_hw_addrs.c
 
clean:
	rm tour arp tour.o arp.o
