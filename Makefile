GCC=gcc
CFLAGS=-Wall -fPIC -shared
LDFLAGS=-ldl
SOURCE=libpreload.c
OBJ=libpreload.so
STRIP=/usr/bin/strip

all: 
	$(GCC) $(CFLAGS) $(SOURCE) -o $(OBJ) $(LDFLAGS)
	#$(STRIP) -s $(OBJ)
	$(GCC) test.c -o 31337test
clean:
	-rm -rf $(OBJ) 31337test
