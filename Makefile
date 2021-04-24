CC = g++

CFLAGS = -pedantic
LDFLAGS = -lpcap

TARGET = ipk-sniffer

all: $(TARGET)

$(TARGET): $(TARGET).cpp
			$(CC) $(CFLAGS) $(TARGET).cpp -o $(TARGET) $(LDFLAGS)

clean:
	$(RM) $(TARGET)

tar:
	tar -cvf xnorek01.tar ipk-sniffer.cpp Makefile manual.pdf README.md