all: bitmsghash.so

run:
	./testpow.py

bitmsghash.so: bitmsghash.o
	g++ bitmsghash.o -shared -fPIC -lpthread -lcrypto -o bitmsghash.so

bitmsghash.o:
	g++ -Wall -O3 -march=native -fPIC -c bitmsghash.cpp

clean:
	rm -f *.o *.so
