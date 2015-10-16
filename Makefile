CC = gcc
CFLAGS = -g
OBJS = clee.o interposition.o
TARGET = interposition

.SUFFIXES : .c .o

all : $(TARGET)

$(TARGET) : $(OBJS)
	$(CC) $(CFLAGS) -o $@ $(OBJS)

clean :
	rm -f $(OBJS) $(TARGET)

clee.o : clee.h clee.c
interposition.o : interposition.h clee.h interposition.c
