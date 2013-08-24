all: bitmsghash.so

bitmsghash.so: bitmsghash.o
	g++ -shared -L/usr/lib -lssl -lcrypto -o bitmsghash.so bitmsghash.o

bitmsghash.o:
	g++ -fpic -c bitmsghash.cpp

clean:
	rm *.o *.so

