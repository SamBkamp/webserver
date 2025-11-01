FLAGS := -Wall -Wextra -pedantic -ggdb

.PHONY: all

pws:main.c
	cc $< ${FLAGS} -o $@

all: pws
