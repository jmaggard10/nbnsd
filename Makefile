CFLAGS += -Wall -Os

all: nbnsd

nbnsd: nbnsd.o
	$(CC) $(CFLAGS) $(LDFLAGS) -s nbnsd.o -o nbnsd

clean:
	rm -f *.o nbnsd *~
