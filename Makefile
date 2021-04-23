CC = g++

LDFLAGS = -lpcap

TARGET = ipk-sniffer

all: $(TARGET)

$(TARGET): $(TARGET).cpp
			$(CC) $(TARGET).cpp -o $(TARGET) $(LDFLAGS)

clean:
	$(RM) $(TARGET)