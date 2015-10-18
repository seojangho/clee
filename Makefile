CC = gcc
CFLAGS = -g -std=c99
CLEE = clee.o syscalls.o simclist.o
TARGET = interpose sandbox warning

.SUFFIXES : .c .o

all : $(TARGET)

$(TARGET) :
	$(CC) $(CFLAGS) -o $@ $^

clean :
	rm -f $(CLEE) $(TARGET) interpose.o sandbox.o warning.o

clee.o : clee.h syscalls.h clee.c
syscalls.o: syscalls.h
simclist.o: simclist.h simclist.c

interpose.o : interpose.h clee.h interpose.c
sandbox.o : sandbox.h clee.h sandbox.c
warning.o : clee.c warning.c

interpose : $(CLEE) interpose.o
sandbox : $(CLEE) sandbox.o
warning : $(CLEE) warning.o
