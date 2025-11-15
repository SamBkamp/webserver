FLAGS := -Wall -Wextra -pedantic -ggdb
LIBS := -lcrypto -lssl

.PHONY: all

pws:main.c string_manipulation.c connections.c
	cc $^ ${FLAGS} -o $@ ${LIBS}

all: pws
