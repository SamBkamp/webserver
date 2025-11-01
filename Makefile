FLAGS := -Wall -Wextra -pedantic -ggdb

.PHONY: all

pws:main.c helper.c
	cc $^ ${FLAGS} -o $@

all: pws
