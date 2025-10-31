FLAGS := -Wall -Wextra -pedantic -ggdb

main:main.c
	cc $< ${FLAGS} -o $@
