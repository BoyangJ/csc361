#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <time.h>

#define MAX_STR_LEN 1024

struct ip_packet {
    char *src_ip;
    char *dst_ip;

    uint16_t src_port;
    uint16_t dst_port;

    unsigned int seq_num;
    unsigned int ack_num;
    uint16_t flag;
    uint16_t window;
    int used;
    int rtt_matched;
    int data_bytes;
    
    struct timeval start_time;
};

struct TCP_hdr {
    u_short th_sport;
    u_short th_dport;
    unsigned int th_seq;
    unsigned int th_ack;
    u_char th_offx2;
    #define TH_OFF(th) (((th)->th_offx2 & 0xf0) >> 4)

    u_char th_flags;
    u_short th_win;
    u_short th_sum;
    u_short th_urp;
};

struct connection {
    char ip_src[MAX_STR_LEN];       //source IP
    char ip_dst[MAX_STR_LEN];       //dest IP
    uint16_t port_src;              //source port #
    uint16_t port_dst;              //dest port #

    int syn_count;                  //flag counters
    int fin_count;
    int rst_count;

    struct timeval start_time;
    struct timeval end_time;
    double duration;

    int num_packet_src;             //# of packets sent by source
    int num_packet_dst;             //# of packets sent by dest
    int num_total_packets;

    int cur_data_len_src;
    int cur_data_len_dst;
    int cur_total_data_len;
    
    uint16_t max_win_size;
    uint16_t min_win_size;
    double sum_win_size;
    
    double min_rtt;
    double max_rtt;
    double sum_rtt;

    int is_set;
};

