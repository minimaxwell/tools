CFLAGS=-I. -lbluetooth -O2 -g -Wall
OBJ = log_reader.o packet.o

all : log_reader

%.o: %.c
	$(CC) -c -o $@ $< $(CFLAGS)

log_reader: $(OBJ)
	$(CC) -o $@ $^ $(CFLAGS)

clean: 
	rm  -f ./*.o
	rm -f log_reader
