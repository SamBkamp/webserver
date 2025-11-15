FLAGS := -Wall -Wextra -pedantic -ggdb
LIBS := -lcrypto -lssl

.PHONY: all

pws:src/main.c src/string_manipulation.c
	cc $^ ${FLAGS} -o $@ ${LIBS}

all: pws
