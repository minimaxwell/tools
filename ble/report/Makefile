CFLAGS = -I. -O2 -g -Wall 
EXTRA_CFLAGS = $(shell pkg-config --cflags gio-unix-2.0)
LDFLAGS = $(shell pkg-config --libs gio-unix-2.0)
TARGET = report
OBJ = report.o report_reader.o main.o

all : $(TARGET)

%.o: %.c
	$(CC) -c -o $@ $< $(CFLAGS) $(EXTRA_CFLAGS)

$(TARGET): $(OBJ)
	$(CC) -o $@ $^ $(CFLAGS) $(LDFLAGS)

clean: 
	rm  -f ./*.o
	rm -f $(TARGET)
