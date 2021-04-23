CC = g++

CFLAGS = -pedantic
LDFLAGS = -lpcap

TARGET = ipk-sniffer

all: $(TARGET)

$(TARGET): $(TARGET).cpp
			$(CC) $(CFLAGS) $(TARGET).cpp -o $(TARGET) $(LDFLAGS)

clean:
	$(RM) $(TARGET)