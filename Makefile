FLAGS := -Wall -Wextra -pedantic -ggdb
LIBS := -lcrypto -lssl

.PHONY: all

pws:main.c helper.c
	cc $^ ${FLAGS} -o $@ ${LIBS}

all: pws
