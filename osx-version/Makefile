GCC=cc
CFLAGS=-Wall -fPIC -shared  -nostdlib -Wl,-undefined,dynamic_lookup -m64
LDFLAGS=-ldl -lc
SOURCE=libpreload.c
OBJ=libpreload.so
STRIP=/usr/bin/strip

all: 
	$(GCC) $(CFLAGS) $(SOURCE) -o $(OBJ) $(LDFLAGS)
	#$(STRIP) -s $(OBJ)
	$(GCC) -Wall -g3 test.c -o 31337test
clean:
	-rm -rf $(OBJ) 31337test
