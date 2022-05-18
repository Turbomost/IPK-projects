/*
 * @Author: Václav Valenta (xvalen29)
 * @Date: 2022-03-04 12:43:00
 * @Last Modified by: Václav Valenta (xvalen29)
 * @Last Modified time: 2022-04-24 17:28:34
 */

#include "sniffer.h"

/**
 * @brief Print error based on argument and exit program
 *
 * @param err input error
 */
void print_error(error_t err) {
    switch (err) {
        case PCAP_DEVS_ERR:
            fprintf(stderr, "pcap_findalldevs error");
            break;
        case INVALID_INTERFACE_ERR:
            fprintf(stderr, "Invalid interface \n");
            break;
        case NO_INTERFACE_ERR:
            fprintf(stderr, "No interface selected\n");
            break;
        case NO_PORT_ERR:
            fprintf(stderr, "No port selected\n");
            break;
        case ARGUMENT_REQ_ERR:
            fprintf(stderr, "Option requires an argument\n");
            break;
        case INVALID_OPTION_ERR:
            fprintf(stderr, "Ivalid option\n");
            break;
        case INTERNAL_ERR:
            fprintf(stderr, "Internal error\n");
            break;
        case PCAP_COMPILE_ERR:
            fprintf(stderr, "pcap_compile error\n");
            break;
        case FILTER_ERR:
            fprintf(stderr, "Filter error\n");
            break;
        default:
            fprintf(stderr, "Other error (%i)\n", err);
            break;
    }
    exit(EXIT_FAILURE);
}

/**
 * @brief Print all interfaces and close program
 *
 * @link Source: Tcpdump [online] <https://www.tcpdump.org/manpages/pcap_findalldevs.3pcap.html> [viewed: 23.04.2022]
 * @link Source: Linux Documentation [online] <https://linux.die.net/man/3/pcap_freealldevs> [viewed: 23.04.2022]
 *
 */
void print_interfaces() {
    pcap_if_t *interface_list;

    if (pcap_findalldevs(&interface_list, NULL) == PCAP_ERROR) {
        print_error(PCAP_DEVS_ERR);
    }

    pcap_if_t *interface;

    for (interface = interface_list; interface != NULL; interface = interface->next) {
        printf("%s\n", interface->name);
    }

    pcap_freealldevs(interface_list);
    free(interface);
    exit(EXIT_SUCCESS);
}

/**
 * @brief Prints timestamp in format yyyy-MM-dd'T'HH:mm:ss.SSSZ
 *
 * @link Source: WinPcap documentation [online] <https://www.winpcap.org/docs/docs_40_2/html/group__wpcap__tut4.html> [viewed: 23.04.2022]
 *
 */
void get_time() {
    time_t rawtime;
    struct tm *info;
    struct timeval tv;
    char buffer[64];
    char offset[16];

    // Get current time
    time(&rawtime);
    info = localtime(&rawtime);
    gettimeofday(&tv, NULL);

    /**
     * @brief Get the miliseconds part
     * @link Source: Stack Overflow [online] <https://stackoverflow.com/questions/3673226/how-to-print-time-in-format-2009-08-10-181754-811> [viewed: 23.04.2022]
     *
     */
    int ms = round(tv.tv_usec / 1000);
    if (ms >= 1000) {
        ms -= 1000;
        tv.tv_sec++;
    }

    /**
     * @brief Print timestamp in the required format
     * @link Source: Sumo Logic Doc Hub [online] <https://help.sumologic.com/03Send-Data/Sources/04Reference-Information-for-Sources/Timestamps%2C-Time-Zones%2C-Time-Ranges%2C-and-Date-Formats> [viewed: 23.04.2022]
     * @link Source: The Open Group Library [online] <https://pubs.opengroup.org/onlinepubs/9699919799/functions/strftime.html> [viewed: 23.04.2022]
     * @link Source: C Standard Library Reference Tutorial [online] <https://www.tutorialspoint.com/c_standard_library/c_function_sprintf.htm> [viewed: 23.04.2022]
     */
    strftime(buffer, 64, "%FT%T", info);
    strftime(offset, 16, "%z", info);
    offset[5] = offset[4];
    offset[4] = offset[3];
    offset[3] = ':';
    printf("timestamp: %s.%03d%s\n", buffer, ms, offset);
}

/**
 * @brief Open interface if available
 *
 * @param interface name of interface in string format
 * @return pcap_t* pointer to opened interface
 *
 * @link Source: Tcpdump [online] <https://www.tcpdump.org/manpages/pcap_open_live.3pcap.html> [viewed: 23.04.2022]
 */
pcap_t *open_interface(char *interface) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *interface_open;
    interface_open = pcap_open_live(interface, 32768, 1, 1000, errbuf);

    if (!interface_open) {
        print_error(INVALID_INTERFACE_ERR);
    }

    return interface_open;
}

/**
 * @brief Set filters for opened interface
 *
 * @param opened_interface pointer to opened interface
 * @param port number of port (or -1)
 * @param tcp boolean value
 * @param udp boolean value
 * @param icmp boolean value
 * @param arp boolean value
 * @return pcap_t* pointer to filetered interface
 *
 * @link Source: Tcpdump [online] <https://www.tcpdump.org/manpages/pcap_setfilter.3pcap.html> [viewed: 23.04.2022]
 * @link Source: Tcpdump [online] <https://www.tcpdump.org/manpages/pcap_compile.3pcap.html> [viewed: 23.04.2022]
 * @link Source: Wireshark documentation [online] <https://www.wireshark.org/docs/wsug_html_chunked/ChCapCaptureFilterSection.html> [viewed: 23.04.2022]
 */
pcap_t *filtration(pcap_t *opened_interface, int port, bool tcp, bool udp, bool icmp, bool arp) {
    struct bpf_program bpf_program_filter;
    int count = 0;
    char filter_string[256] = "(";
    char port_filter[128] = "";

    // Set filters for protocols
    if (tcp) {
        strcat(filter_string, "(tcp)");
        count++;
    }

    if (udp) {
        if (count)
            strcat(filter_string, "or");
        strcat(filter_string, "(udp)");
        count++;
    }

    if (icmp) {
        if (count)
            strcat(filter_string, "or");
        strcat(filter_string, "(icmp)");
        count++;
    }

    if (arp) {
        if (count)
            strcat(filter_string, "or");
        strcat(filter_string, "(arp)");
        count++;
    }
    strcat(filter_string, ")");

    // Add filter for port
    if (port != -1) {
        // Check invalid filter combination
        if (arp || icmp) {
            strcpy(filter_string, "");
            sprintf(port_filter, "port %d", port);
        } else {
            sprintf(port_filter, " and port %d", port);
        }
    }
    strcat(filter_string, port_filter);

    // Use filters and return filetered interface
    if (pcap_compile(opened_interface, &bpf_program_filter, filter_string, 0, PCAP_NETMASK_UNKNOWN) == -1) {
        pcap_close(opened_interface);
        print_error(PCAP_COMPILE_ERR);
    }

    if (pcap_setfilter(opened_interface, &bpf_program_filter) == -1) {
        pcap_close(opened_interface);
        print_error(FILTER_ERR);
    }

    /**
     * @brief Free memory
     * @link Source: Linux Documentation [online] <https://linux.die.net/man/3/pcap_freecode> [viewed: 23.04.2022]
     */
    pcap_freecode(&bpf_program_filter);
    return opened_interface;
}

/**
 * @brief Print the specified MAC address
 *
 * @param ptr pointer to first char of mac address
 * @param str string to be printed
 * @param length ETHER_ADDR_LEN parameter
 *
 * @link Source: Capturing Our First Packet [online] <http://yuba.stanford.edu/~casado/pcap/section2.html> [viewed: 24.04.2022]
 */
void get_mac(u_char *ptr, char str[], int length) {
    int i = length;
    printf("%s", str);
    while (i > 0) {
        if (i == length)
            printf("%.2x", *ptr++);
        else
            printf(":%.2x", *ptr++);
        i--;
    }
    printf("\n");
}

/**
 * @brief Print data in hexadecimal and ascii format on one line
 *
 * @param data u_char string of data
 * @param size size of string
 * @param offset line offset
 *
 * @link Source: Tcpdump [online] <https://www.tcpdump.org/other/sniffex.c> [viewed: 24.04.2022]
 */
void print_hex_ascii(const u_char *data, int size, int offset) {
    // String of data
    const u_char *hex_data;

    // Offset used for 0x0000 format
    printf("0x%04x: ", offset);

    // Print 16 hexadecimal values
    hex_data = data;
    for (int index = 0; index < 16; index++) {
        if (index < size) {
            printf("%02x ", *hex_data);
        } else {
            printf("   ");
        }
        if ((index + 1) % 8 == 0) {
            printf(" ");
        }
        hex_data++;
    }

    // Print ASCII values
    for (int index = 0; index < 16; index++) {
        if (index < size) {
            if (isprint(*data)) {
                printf("%c", *data);
            } else {
                printf(".");
            }
        }
        if (index == 7) {
            printf(" ");
        }
        data++;
    }

    printf("\n");
}

/**
 * @brief Calculate data offsets and print them
 *
 * @param data data string
 * @param size size of data
 *
 * @link Source: How to code a Packet Sniffer in C with Libpcap on Linux [online] <https://www.binarytides.com/packet-sniffer-code-c-libpcap-linux-sockets> [viewed: 24.04.2022]
 * @link Source: Tcpdump [online] <https://www.tcpdump.org/other/sniffex.c> [viewed: 24.04.2022]
 */
void print_data(const u_char *data, int size) {
    // Offset used for 0x0000 format
    int offset = 0;

    // String of data
    const u_char *char_data = data;

    // Size of data left to be written
    int size_left = size;
    int line_length;

    // If there are no data to be printed - return
    if (size <= 0) {
        return;
    }

    // Print whole lines, until the size is smaller than one line
    while (size_left > 16) {
        line_length = 16 % size_left;
        print_hex_ascii(char_data, line_length, offset);
        size_left -= line_length;
        char_data += line_length;
        offset += 16;
    }

    // Print the last line
    print_hex_ascii(char_data, size_left, offset);
    return;
}

/**
 * @brief Callback function for processing packets
 *
 * @param user
 * @param header
 * @param bytes
 *
 * @link Source: Using libpcap in C [online] <https://www.devdungeon.com/content/using-libpcap-c#pcap-loop> [viewed: 24.04.2022]
 * @link Source: WinPcap documentation [online] <https://www.winpcap.org/docs/docs_412/html/structpcap__pkthdr.html> [viewed: 24.04.2022]
 * @link Source: Wikipedia [online] <https://en.wikipedia.org/wiki/Ethernet_frame> [viewed: 24.04.2022]
 * @link Source: netinet/if_ether.h documentation [online] <https://unix.superglobalmegacorp.com/Net2/newsrc/netinet/if_ether.h.html> [viewed: 24.04.2022]
 * @link Source: Tcpdump [online] <https://samy.pl/packet/MISC/tcpdump-3.7.1/ethertype.h> [viewed: 24.04.2022]
 * @link Source: netinet/in.h documentation [online] <https://pubs.opengroup.org/onlinepubs/009695399/basedefs/netinet/in.h.html> [viewed: 24.04.2022]
 */
void sniffing(u_char *user, const struct pcap_pkthdr *header, const u_char *packet) {
    struct ether_header *eth_header;
    eth_header = (struct ether_header *)packet;

    get_time();
    get_mac(eth_header->ether_shost, "src MAC: ", ETHER_ADDR_LEN);
    get_mac(eth_header->ether_dhost, "dst MAC: ", ETHER_ADDR_LEN);
    printf("frame length: %i bytes\n", header->len);

    /**
     * @brief Get informations from ARP packet
     * @link Source: ether_arp Struct Reference [online] <http://www.ethernut.de/api/structether__arp.html> [viewed: 24.04.2022]
     * @link Source: Jeremiah Mahler - socket-examples [online] <https://github.com/jmahler/socket-examples/blob/master/packets/packets.c> [viewed: 24.04.2022]
     */
    if (ntohs(eth_header->ether_type) == ETHERTYPE_ARP) {
        struct ether_arp *arp_struct = (struct ether_arp *)packet;
        char ip[INET_ADDRSTRLEN];

        inet_ntop(AF_INET, &(arp_struct->arp_spa), ip, INET_ADDRSTRLEN);
        printf("src IP: %s\n", ip);

        inet_ntop(AF_INET, &(arp_struct->arp_tpa), ip, INET_ADDRSTRLEN);
        printf("dst IP: %s\n", ip);
    }

    /**
     * @brief Get informations from IPv4 packet
     * @link Source: Assigned Internet Protocol Numbers [online] <https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml> [viewed: 24.04.2022]
     * @link Source: Sniffer example of TCP/IP packet capture using libpcap [online] <https://www.tcpdump.org/other/sniffex.c> [viewed: 24.04.2022]
     */
    else if (ntohs(eth_header->ether_type) == ETHERTYPE_IP) {
        struct ip *ip4_header = (struct ip *)(packet + sizeof(struct ether_header));
        struct sockaddr_in icmp_ip4;

        icmp_ip4.sin_addr.s_addr = ip4_header->ip_src.s_addr;
        printf("src IP: %s\n", inet_ntoa(icmp_ip4.sin_addr));

        icmp_ip4.sin_addr.s_addr = ip4_header->ip_dst.s_addr;
        printf("dst IP: %s\n", inet_ntoa(icmp_ip4.sin_addr));

        // TCPv4
        if (ip4_header->ip_p == 6) {
            struct tcphdr *ip4_tcp = (struct tcphdr *)(packet + (ip4_header->ip_hl * 4) + sizeof(struct ether_header));

            printf("src port: %u\n", ntohs(ip4_tcp->th_sport));
            printf("dst port: %u\n", ntohs(ip4_tcp->th_dport));
        }

        // UDP
        else if (ip4_header->ip_p == 17) {
            struct udphdr *ip4_udp = (struct udphdr *)(packet + (ip4_header->ip_hl * 4) + sizeof(struct ether_header));

            printf("src port: %u\n", ntohs(ip4_udp->uh_sport));
            printf("dst port: %u\n", ntohs(ip4_udp->uh_dport));
        }
    }

    /**
     * @brief Get informations from IPv6 packet
     * @link Source: Assigned Internet Protocol Numbers [online] <https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml> [viewed: 24.04.2022]
     * @link Source: Understanding the IPv6 Header [online] <https://www.microsoftpressstore.com/articles/article.aspx?p=2225063&seqNum=3> [viewed: 24.04.2022]
     */
    else if (ntohs(eth_header->ether_type) == ETHERTYPE_IPV6) {
        struct ip6_hdr *ip6_header = (struct ip6_hdr *)(packet + sizeof(struct ether_header));

        // ICMPv6
        if (ip6_header->ip6_ctlun.ip6_un1.ip6_un1_nxt == 58) {
        }

        // TCPv6
        if (ip6_header->ip6_ctlun.ip6_un1.ip6_un1_nxt == 6) {
            struct tcphdr *ip6_tcp = (struct tcphdr *)(packet + 40 + sizeof(struct ether_header));
            printf("src port : %u\n", ntohs(ip6_tcp->th_sport));
            printf("dst port : %u\n", ntohs(ip6_tcp->th_dport));
        }

        // UDPv6
        else if (ip6_header->ip6_ctlun.ip6_un1.ip6_un1_nxt == 17) {
            struct udphdr *ip6_udp = (struct udphdr *)(packet + 40 + sizeof(struct ether_header));
            printf("src port: %u\n", ntohs(ip6_udp->uh_sport));
            printf("dst port: %u\n", ntohs(ip6_udp->uh_dport));
        }
    }

    print_data(packet, header->len);
    printf("\n");
}

// --- MAIN ---
int main(int argc, char **argv) {
    char interface[32] = "-1";
    int port = -1;
    int num = 1;
    bool icmp, tcp, udp, arp;
    icmp = tcp = udp = arp = false;

    /**
     * @brief Create long_opt structure
     * @link Source: Linux Documentation [online] <https://linux.die.net/man/3/getopt_long> [viewed: 23.04.2022]
     */
    struct option long_opt[] =
        {
            {"interface", required_argument, NULL, 'i'},
            {"icmp", no_argument, NULL, 'c'},
            {"tcp", no_argument, NULL, 't'},
            {"udp", no_argument, NULL, 'u'},
            {"arp", no_argument, NULL, 'a'},
            {NULL, no_argument, NULL, 0}};

    /**
     * @brief Get command line options
     * @link Source: Stack Overflow [online] <https://stackoverflow.com/questions/19604413/getopt-optional-arguments> [viewed: 23.04.2022]
     * @link Source: Stack Overflow [online] <https://stackoverflow.com/questions/7489093/getopt-long-proper-way-to-use-it> [viewed: 23.04.2022]
     * @link Source: Stack Overflow [online] <https://stackoverflow.com/questions/9642732/parsing-command-line-arguments-in-c> [viewed: 23.04.2022]
     * @link Source: getopt() function in C to parse command line arguments [online] <https://www.tutorialspoint.com/getopt-function-in-c-to-parse-command-line-arguments> [viewed: 23.04.2022]
     * @link Source: Robbins, A. (2004). Linux programming by example (1st ed.). Prentice Hall. ISBN 9780131429642
     */
    int option;
    while ((option = getopt_long(argc, argv, ":i:p:n:tu", long_opt, NULL)) != -1) {
        switch (option) {
            case 'i':
                if (optarg[0] == '-') {
                    print_error(NO_INTERFACE_ERR);
                } else {
                    strcpy(interface, optarg);
                }
                break;

            case 'c':
                icmp = true;
                break;

            case 'p':
                if (optarg[0] == '-') {
                    print_error(NO_PORT_ERR);
                } else {
                    port = atoi(optarg);
                }
                break;

            case 't':
                tcp = true;
                break;

            case 'u':
                udp = true;
                break;

            case 'n':
                num = atoi(optarg);
                break;

            case 'a':
                arp = true;
                break;

            // No arguments for the required options
            case ':':
                switch (optopt) {
                    // No arguments for -i option -> print all interfacess
                    case 'i':
                        print_interfaces();
                        break;
                    default:
                        print_error(ARGUMENT_REQ_ERR);
                }
                break;

            // Invalid option
            case '?':
            default:
                print_error(INVALID_OPTION_ERR);
        };
    };

    // Check if interface is selected
    if (!strcmp(interface, "-1")) {
        print_interfaces();
    }

    // Check if protocols are specified
    if (!(tcp || udp || icmp || arp))
        tcp = udp = icmp = arp = true;

    // Open interface and set filters
    pcap_t *opened_interface = open_interface(interface);
    opened_interface = filtration(opened_interface, port, tcp, udp, icmp, arp);
    pcap_loop(opened_interface, num, sniffing, NULL);
    pcap_close(opened_interface);

    exit(EXIT_SUCCESS);
    return 0;
}