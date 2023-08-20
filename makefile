CC=gcc
CFLAGS= -pthread -Wall -Wextra -Wpedantic -Werror

all: r

c: r.c

.PHONY:
clean:
	rm -f r
