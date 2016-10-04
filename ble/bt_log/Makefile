CFLAGS=-I. -lbluetooth -O2 -g -Wall
OBJ = bt_log.o monitor.o

all : bt_log

%.o: %.c
	$(CC) -c -o $@ $< $(CFLAGS)

bt_log: $(OBJ)
	$(CC) -o $@ $^ $(CFLAGS)

clean: 
	rm  -f ./*.o
	rm -f bt_log
