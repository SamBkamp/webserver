FLAGS := -Wall -Wextra -pedantic -ggdb

.PHONY: all

main:main.c
	cc $< ${FLAGS} -o $@

all: main
