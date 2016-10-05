CFLAGS=-I. -lbluetooth -O2 -g -Wall -DHAVE_UDEV_HWDB_NEW -ludev
OBJ = bdaddr.o hwdb.o

all : bdaddr

%.o: %.c
	$(CC) -c -o $@ $< $(CFLAGS)

bdaddr: $(OBJ)
	$(CC) -o $@ $^ $(CFLAGS)

clean: 
	rm  -f ./*.o
	rm -f bdaddr
