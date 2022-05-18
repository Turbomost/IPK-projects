#define _GNU_SOURCE

#include <ctype.h>
#include <getopt.h>
#include <math.h>
#include <netinet/ether.h>
#include <netinet/icmp6.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <pcap/pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

// Error enumeration
typedef enum error_enum {
    PCAP_DEVS_ERR,
    INVALID_INTERFACE_ERR,
    NO_INTERFACE_ERR,
    NO_PORT_ERR,
    ARGUMENT_REQ_ERR,
    INVALID_OPTION_ERR,
    INTERNAL_ERR,
    PCAP_COMPILE_ERR,
    FILTER_ERR
} error_t;

// Funciton declarations
void print_error(error_t);
void print_interfaces();
void get_time();
pcap_t *open_interface(char[]);
pcap_t *filtration(pcap_t *, int, bool, bool, bool, bool);
void sniffing(u_char *, const struct pcap_pkthdr *, const u_char *);
void get_mac(u_char *, char[], int);
void print_hex_ascii(const u_char *, int, int);
void print_data(const u_char *, int);