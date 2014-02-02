GCC=gcc
CFLAGS=-Wall -fPIC -shared
LDFLAGS=-ldl
SOURCE=libpreload.c
TARGET=libpreload.so
STRIP=/usr/bin/strip

all: 
	$(GCC) $(CFLAGS) $(SOURCE) -o $(TARGET) $(LDFLAGS)
	$(GCC) $(CFLAGS) test.c -o 31337/31337test

clean:
	-rm $(TARGET) 31337/31337test
