/*
 * @Author: Václav Valenta (xvalen29)
 * @Date: 2022-03-01 11:36:50
 * @Last Modified by: Václav Valenta (xvalen29)
 * @Last Modified time: 2022-04-19 10:51:46
 */

#define _GNU_SOURCE
#define E404 "HTTP/1.1 404 Not Found\r\n\r\n"
#define E400 "HTTP/1.1 400 Bad Request\r\n\r\n"
#define HEAD "HTTP/1.1 200 OK\r\nContent-Type:text/plain;\r\n\r\n"

#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

void error_message(int);
void get_cpu_load(int);
void send_response(int, char *);
void get_hostname(int);
void get_cpu_name(int);

// Error enumeration
typedef enum {
    PORT_ERR,
    SOCKET_ERR,
    SETSOCKETOPT_ERR,
    BIND_ERR,
    LISTEN_ERR,
    ACCEPT_ERR,
    FILE_ERR
} error_type;

/**
 * @brief Calculate the CPU current load
 *
 * @param new_socket socket number
 */
void get_cpu_load(int new_socket) {
    double User, Nice, System, Idle, Iowait, Irq, Softirq, Steal, PrevUser, PrevNice, PrevSystem, PrevIdle, PrevIowait, PrevIrq, PrevSoftirq, PrevSteal;
    FILE *proc_file = fopen("/proc/stat", "r");
    if (proc_file == NULL)
        error_message(FILE_ERR);

    fscanf(proc_file, "cpu %lf %lf %lf %lf %lf %lf %lf %lf", &PrevUser, &PrevNice, &PrevSystem, &PrevIdle, &PrevIowait, &PrevIrq, &PrevSoftirq, &PrevSteal);
    sleep(1);
    rewind(proc_file);
    fscanf(proc_file, "cpu %lf %lf %lf %lf %lf %lf %lf %lf", &User, &Nice, &System, &Idle, &Iowait, &Irq, &Softirq, &Steal);
    fclose(proc_file);

    double prev_sum = PrevUser + PrevNice + PrevSystem + PrevIdle + PrevIowait + PrevIrq + PrevSoftirq + PrevSteal;
    double sum = User + Nice + System + Idle + Iowait + Irq + Softirq + Steal;
    double total_dif = sum - prev_sum;
    double idle_dif = Idle + Iowait - (PrevIdle + PrevIowait);
    double CPU_Percentage = ((total_dif - idle_dif) / total_dif) * 100.0;

    char output[1024];
    snprintf(output, 1024, "%g%%\n", CPU_Percentage);
    send_response(new_socket, output);
}

/**
 * @brief Get hostname
 *
 * @param new_socket socket number
 */
void get_hostname(int new_socket) {
    char host_name[256];
    FILE *host_file = fopen("/proc/sys/kernel/hostname", "r");
    if (host_file == NULL)
        error_message(FILE_ERR);

    fgets(host_name, 256, host_file);
    fclose(host_file);

    send_response(new_socket, host_name);
}

/**
 * @brief Get cpu name
 *
 * @param new_socket socket number
 */
void get_cpu_name(int new_socket) {
    char cpu_name[256];

    FILE *cpu_file = popen("cat /proc/cpuinfo | grep 'model name' | uniq | cut -f 2 -d : | awk '{$1=$1}1'", "r");
    if (cpu_file == NULL)
        error_message(FILE_ERR);

    fgets(cpu_name, 256, cpu_file);
    pclose(cpu_file);

    send_response(new_socket, cpu_name);
}

/**
 * @brief Send response
 *
 * @param new_socket socket number
 * @param output output string
 */
void send_response(int new_socket, char *value) {
    char output[1024];
    strcpy(output, HEAD);
    strcat(output, value);

    send(new_socket, output, strlen(output), 0);
}

/**
 * @brief Print error message and shut down
 *
 * @param error string of error type
 */
void error_message(int error) {
    switch (error) {
        case PORT_ERR:
            perror("Port error");
            break;
        case SOCKET_ERR:
            perror("Socket error");
            break;
        case SETSOCKETOPT_ERR:
            perror("SetSocketOpt error");
            break;
        case LISTEN_ERR:
            perror("Listen error");
            break;
        case BIND_ERR:
            perror("Bind error");
            break;
        case ACCEPT_ERR:
            perror("Accept error");
            break;
        case FILE_ERR:
            perror("File error");
            break;
    }
    exit(error);
}

// Main function
int main(int argc, char **argv) {
    int PORT, new_socket, server_fd;
    struct sockaddr_in address;
    int addrlen = sizeof(address);
    int opt = 1;
    char buffer[512];

    // Port check
    if (argc < 2)
        error_message(PORT_ERR);
    else
        PORT = atoi(argv[1]);

    // Create and set up socket
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0)
        error_message(SOCKET_ERR);

    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)))
        error_message(SETSOCKETOPT_ERR);
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);

    // Bind and listen
    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0)
        error_message(BIND_ERR);

    if (listen(server_fd, 3) < 0)
        error_message(LISTEN_ERR);

    // Connect
    while (1) {
        if ((new_socket = accept(server_fd, (struct sockaddr *)&address, (socklen_t *)&addrlen)) < 0)
            error_message(ACCEPT_ERR);

        // Get first line from the buffer and compare
        read(new_socket, buffer, 512);
        char *first_line = strtok(buffer, "\n");

        if (strstr(first_line, "GET /cpu-name")) {
            get_cpu_name(new_socket);
        } else if (strstr(first_line, "GET /load")) {
            get_cpu_load(new_socket);
        } else if (strstr(first_line, "GET /hostname")) {
            get_hostname(new_socket);
        } else if (strstr(first_line, "GET /favicon.ico")) {
            send(new_socket, E404, strlen(E404), 0);
        } else {
            send(new_socket, E400, strlen(E400), 0);
        }

        // Close socket
        close(new_socket);
    }

    return 0;
}