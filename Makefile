CC=gcc

INCLUDE=`libnet-config --defines` -I/usr/local/include
LIBS=-lpcap -L/usr/local/lib `libnet-config --libs`

CFLAGS= -g -DDEBUG=1 -Wall $(INCLUDE)

SRCS=wonky.c
SHARED_OBJS=
OBJS=wonky.o
PROGS=wonky

all: $(SRCS) $(PROGS)

wonky: ${OBJS}
	$(CC) $(LDFLAGS) -o $@ $@.o ${SHARED_OBJS} ${LIBS}

.c.o:
	$(CC) $(CFLAGS) -c $<

clean:
	rm $(PROGS) *.o
