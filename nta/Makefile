CC=gcc
CFLAGS=-O2 -c -g -I ..
LDFLAGS=-g 
SOURCES=send.c sniff.c control.c
OBJECTS_SNIFF = sniff.o control.o
OBJECTS_SEND = send.o control.o

all: send sniff
	
sniff: $(OBJECTS_SNIFF)
	$(CC) $(LDFLAGS) $(OBJECTS_SNIFF) -o $@
send: $(OBJECTS_SEND)
	$(CC) $(LDFLAGS) $(OBJECTS_SEND) -o $@
.c.o:
	$(CC) $(CFLAGS) $< -o $@

clean:
	rm *.o; rm send; rm sniff
	
		

