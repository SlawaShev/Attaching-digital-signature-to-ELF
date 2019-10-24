CC=gcc
CFLAGS=-lssl -lcrypto

build: main.cpp
	$(CC) main.cpp $(CFLAGS)
