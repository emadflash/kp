CC = gcc
EXEC = kp
CFLAGS = -fsanitize=address -Wall -g -std=c99

all: example.c kp.h
	gcc ${CFLAGS} example.c kp.h -o example
