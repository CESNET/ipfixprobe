all: probe

probe: main.c parser.c cache.c xxhash.c ipfix.c plugin.c regex.c plugin.h regex.h parser.h  cache.h types.h ipfix.c ipfix.h
	gcc main.c parser.c cache.c xxhash.c ipfix.c plugin.c regex.c -Wall -g -O0 -lpcap -o probe
