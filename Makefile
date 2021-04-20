CC = g++

CFLAGS = -g -Wall -Wextra
LDFLAGS = -lpcap

TARGET = ipk-sniffer

all: $(TARGET)

$(TARGET): $(TARGET).cpp
			$(CC) $(CFLAGS) -o $(TARGET) $(TARGET).cpp $(LDFLAGS)

clean:
	$(RM) $(TARGET)