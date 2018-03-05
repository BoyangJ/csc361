#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <time.h>

#define MAX_STR_LEN 1024

struct router {
    char *ip;

    int num_connections;

    double RTT[100];
    
    double RTT_avg;
    double RTT_sd;
    
};

struct packet_time {
    struct timeval time;

    char *ip;
    uint16_t src_port;
    int id;

};

