CC = gcc
CFLAGS = -g -std=c99
OBJS = clee.o interpose.o syscalls.o simclist.o
TARGET = interpose

.SUFFIXES : .c .o

all : $(TARGET)

$(TARGET) : $(OBJS)
	$(CC) $(CFLAGS) -o $@ $(OBJS)

clean :
	rm -f $(OBJS) $(TARGET)

clee.o : clee.h syscalls.h clee.c
syscalls.o: syscalls.h
interpose.o : interpose.h clee.h interpose.c
simclist.o: simclist.h simclist.c
