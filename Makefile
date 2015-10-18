CC = gcc
CFLAGS = -g -std=c99
CLEE = clee.o syscalls.o simclist.o
TARGET = interpose sandbox

.SUFFIXES : .c .o

all : $(TARGET)

$(TARGET) :
	$(CC) $(CFLAGS) -o $@ $^

clean :
	rm -f $(CLEE) $(TARGET) interpose.o sandbox.o

clee.o : clee.h syscalls.h clee.c
syscalls.o: syscalls.h
simclist.o: simclist.h simclist.c

interpose.o : interpose.h clee.h interpose.c
sandbox.o : sandbox.h clee.h sandbox.c

interpose : $(CLEE) interpose.o
sandbox : $(CLEE) sandbox.o
