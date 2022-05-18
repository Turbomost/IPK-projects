CC=gcc
CFLAGS=-Wall -std=c11 -pedantic -lm -ggdb3 -g
FILES= sniffer.c sniffer.h

.PHONY: ipk-sniffer clean

all:ipk-sniffer

# Source: Stack Overflow [online] <https://stackoverflow.com/questions/31167588/undefined-reference-to-pcap> [viewed: 22.04.2022]
ipk-sniffer: $(FILES)
	$(CC) $(CFLAGS) -o $@ $(FILES) -lpcap

clean:
	@rm -f ipk-sniffer