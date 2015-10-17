CC = gcc
CFLAGS = -g -std=c99
OBJS = clee.o interposition.o syscalls.o
TARGET = interposition

.SUFFIXES : .c .o

all : $(TARGET)

$(TARGET) : $(OBJS)
	$(CC) $(CFLAGS) -o $@ $(OBJS)

clean :
	rm -f $(OBJS) $(TARGET)

clee.o : clee.h syscalls.h clee.c
syscalls.o: syscalls.h
interposition.o : interposition.h clee.h interposition.c
