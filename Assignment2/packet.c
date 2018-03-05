/*------------------------------
* Name: Boyang Jiao
* UvicID: V00800928
* Date: June 24, 2016
*
* packet.c
* Description: Reads and analyses a packet trace file.
* CSC 361
* Instructor: Kui Wu
-------------------------------*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <time.h>

#include <netinet/in.h>
#include <netinet/ip.h>
#include <net/if.h>
#include <netinet/if_ether.h>
#include <netinet/tcp.h>
#include <pcap/pcap.h>

#include <arpa/inet.h>

#include "util.c"

#define DEBUG 0
#define MAX_STR_LEN 1024

#define CHECK_BIT(var,pos) ((var) & (1<<(pos)))     //checks whether bit at pos is 1

int total_packets = 0;
struct ip_packet all_packets[4096];

int total_connections = 0;
struct connection all_connections[1024];

struct timeval first_packet;

//function prototypes
void parse_packet(const unsigned char *packet, struct timeval ts, unsigned int capture_len);
const char *timestamp_string(struct timeval ts);
void check_connections();
void print_connections();
void print_general_info();
void print_numerical_info();
struct timeval timeval_subtract (struct timeval x, struct timeval y);

void parse_packet(const unsigned char *packet, struct timeval ts, unsigned int capture_len) {
    struct ip *ip;
	struct TCP_hdr *tcp;
	unsigned int ip_header_length;

    //save timestamp of first packet, to be used in later time calculations
    if (total_packets == 0) first_packet = ts;

    //check if packet at least as long as ethernet header
    if (capture_len < sizeof(struct ether_header)) {
        printf("Packet at timestamp %s does not have a full Ethernet header.\n", timestamp_string(timeval_subtract(ts, first_packet)));
        return;
    }

    //skip the Ethernet header
	packet += sizeof(struct ether_header);
	capture_len -= sizeof(struct ether_header);

    //check if packet has IP header
    if (capture_len < sizeof(struct ip)) {
        printf("Packet at timestamp %s does not have a full IP header.\n", timestamp_string(timeval_subtract(ts, first_packet)));
        return;
    }

    //calculate ip header length
    ip = (struct ip*) packet;       //ip now points to start of IP header
	ip_header_length = ip->ip_hl * 4;

    if (capture_len < ip_header_length) {
        printf("Packet at timestamp %s not good.\n", timestamp_string(timeval_subtract(ts, first_packet)));
        return;
    }

    //check if packet is TCP protocol
    if (ip->ip_p != IPPROTO_TCP) {
		printf("Packet at timestamp %s not TCP.\n", timestamp_string(timeval_subtract(ts, first_packet)));
		return;
	}

    //skip ip header to find TCP header
    packet += ip_header_length;
	capture_len -= ip_header_length;

    //check if packet has TCP header
    if (capture_len < sizeof(struct tcphdr)) {
        printf("Packet at timestamp %s does not have a full TCP header.\n", timestamp_string(timeval_subtract(ts, first_packet)));
        return;
    }

    tcp = (struct TCP_hdr*) packet;      //tcp now point to start of tcp header;

    // --- Store packet information in all_packets ---
    //source and dest IP addresses
    char *addr = inet_ntoa(ip->ip_src);
    all_packets[total_packets].src_ip = (char*) malloc(100);
    strcpy(all_packets[total_packets].src_ip, addr);
    int size = strlen(all_packets[total_packets].src_ip);
    all_packets[total_packets].src_ip[size] = '\0';

    addr = inet_ntoa(ip->ip_dst);
    all_packets[total_packets].dst_ip = (char*) malloc(100);
    strcpy(all_packets[total_packets].dst_ip, addr);
    size = strlen(all_packets[total_packets].dst_ip);
    all_packets[total_packets].dst_ip[size] = '\0';

    //source and dest port numbers
    all_packets[total_packets].src_port = ntohs(tcp->th_sport);
    all_packets[total_packets].dst_port = ntohs(tcp->th_dport);

    //sequence and acknowledgement numbers
    all_packets[total_packets].seq_num = ntohl(tcp->th_seq);
    all_packets[total_packets].ack_num = ntohl(tcp->th_ack);

    //other tcp header information
    all_packets[total_packets].flag = (unsigned int)tcp->th_flags;
    all_packets[total_packets].window = ntohs(tcp->th_win);
    all_packets[total_packets].used = -1;
    int data = capture_len - (TH_OFF(tcp) * 4);
    all_packets[total_packets].data_bytes = data;
    all_packets[total_packets].start_time = ts;

}

void check_connections() {
    //loop through all the packets
    int i, j;
    for (i = 0; i < total_packets; i++) {
        int i_is_new = 1;           //tracks whether packet i is a new connection
        
        //loop through all previous packets
        for (j = 0; j < i; j++) {

            if (i_is_new == 1) {
                //check if src and dst info match
                if ((all_packets[i].src_port == all_packets[j].src_port && all_packets[i].dst_port == all_packets[j].dst_port
                    && !strcmp(all_packets[i].src_ip, all_packets[j].src_ip) && !strcmp(all_packets[i].dst_ip, all_packets[j].dst_ip)) ||
                    (all_packets[i].dst_port == all_packets[j].src_port && all_packets[i].src_port == all_packets[j].dst_port
                    && !strcmp(all_packets[i].dst_ip, all_packets[j].src_ip) && !strcmp(all_packets[i].src_ip, all_packets[j].dst_ip))) {

                    //matches
                    all_packets[i].used = all_packets[j].used;

                    //check if packet is SYN, FIN, or RST
                    if (CHECK_BIT(all_packets[i].flag, 1)) {
                        all_connections[all_packets[i].used].syn_count++;
                      
                    }
                    if (CHECK_BIT(all_packets[i].flag, 0)) {
                        all_connections[all_packets[i].used].fin_count++;
                        
                    }
                    if (CHECK_BIT(all_packets[i].flag, 2)) {
                        all_connections[all_packets[i].used].rst_count++;
                    }

                    //set end time and duration of connection (since this is the latest packet processed for this connection)
                    all_connections[all_packets[i].used].end_time = timeval_subtract(all_packets[i].start_time, first_packet);
                    all_connections[all_packets[i].used].duration = atof(timestamp_string(timeval_subtract(all_connections[all_packets[i].used].end_time, all_connections[all_packets[i].used].start_time)));

                    //figure out if sent by source or dest
                    //sent by source
                    if (!strcmp(all_packets[i].src_ip, all_connections[all_packets[i].used].ip_src)) {
                        //increment # of packets from source
                        all_connections[all_packets[i].used].num_packet_src++;
                        
                        //increase data length from source
                        all_connections[all_packets[i].used].cur_data_len_src += all_packets[i].data_bytes;
    
                    //sent by dest
                    } else if (!strcmp(all_packets[i].src_ip, all_connections[all_packets[i].used].ip_dst)) {
                        //increment # of packets from dest
                        all_connections[all_packets[i].used].num_packet_dst++;

                        //increase data length from dest
                        all_connections[all_packets[i].used].cur_data_len_dst += all_packets[i].data_bytes;
                    }

                    all_connections[all_packets[i].used].num_total_packets++;
                    all_connections[all_packets[i].used].cur_total_data_len += all_packets[i].data_bytes;

                    //update window size properties
                    if (all_packets[i].window > all_connections[all_packets[i].used].max_win_size) {
                        all_connections[all_packets[i].used].max_win_size = all_packets[i].window;

                    } else if (all_packets[i].window < all_connections[all_packets[i].used].min_win_size) {
                        all_connections[all_packets[i].used].min_win_size = all_packets[i].window;
                    }

                    all_connections[all_packets[i].used].sum_win_size += all_packets[i].window;


                    i_is_new = 0;
                    //break;

                } //if 

            } //if i_is_new

            //find packet j that packet i is matched with for RTT calculations
            if (all_packets[j].rtt_matched == 0) {
                //if packet is data packet, find corresponding matching packet
                if (!CHECK_BIT(all_packets[i].flag, 0)) {
                    if (all_packets[i].ack_num == (all_packets[j].seq_num + all_packets[j].data_bytes)) {
                        //printf("RTT PAIR HERE\n");
                        double rtt = atof(timestamp_string(timeval_subtract(all_packets[i].start_time, all_packets[j].start_time)));

                        if (rtt < all_connections[all_packets[i].used].min_rtt) { all_connections[all_packets[i].used].min_rtt = rtt; }

                        if (rtt > all_connections[all_packets[i].used].max_rtt) { all_connections[all_packets[i].used].max_rtt = rtt; }

                        all_connections[all_packets[i].used].sum_rtt += rtt;

                        all_packets[i].rtt_matched = 1;
                        all_packets[j].rtt_matched = 1;
                        break;
                    }
                }

                //if packet is ACK, find the matching SYN
                if (CHECK_BIT(all_packets[i].flag, 4)) {
                    if (all_packets[i].ack_num == all_packets[j].seq_num+1) {
                        double rtt = atof(timestamp_string(timeval_subtract(all_packets[i].start_time, all_packets[j].start_time)));
                      
                        if (rtt < all_connections[all_packets[i].used].min_rtt) { all_connections[all_packets[i].used].min_rtt = rtt; }

                        if (rtt > all_connections[all_packets[i].used].max_rtt) { all_connections[all_packets[i].used].max_rtt = rtt; }

                        all_connections[all_packets[i].used].sum_rtt += rtt;

                        all_packets[i].rtt_matched = 1;
                        all_packets[j].rtt_matched = 1;
                        break;
                    }
                }
                    
            } //if rtt_matched
                

        } //for

        //i did not match any previous packets (create new connection)
        if (i_is_new == 1) {
            //create new connection
            all_packets[i].used = total_connections;

            //fill in source and dest IP and port #
            strcpy(all_connections[total_connections].ip_src, all_packets[i].src_ip);
            strcpy(all_connections[total_connections].ip_dst, all_packets[i].dst_ip);
            all_connections[total_connections].port_src = all_packets[i].src_port;
            all_connections[total_connections].port_dst = all_packets[i].dst_port;

            //check if packet is SYN, FIN, or RST
            if (CHECK_BIT(all_packets[i].flag, 1)) {
                all_connections[total_connections].syn_count++;
               
            }
            if (CHECK_BIT(all_packets[i].flag, 0)) {
                all_connections[total_connections].fin_count++;
                
            }
            if (CHECK_BIT(all_packets[i].flag, 2)) {
                all_connections[total_connections].rst_count++;
            }

            //set start time of new connection
            all_connections[all_packets[i].used].start_time = timeval_subtract(all_packets[i].start_time, first_packet);

            //increment # of packets from source
            all_connections[total_connections].num_packet_src++;
            all_connections[total_connections].num_total_packets++;

            //increase data length from source
            all_connections[total_connections].cur_data_len_src += all_packets[i].data_bytes;
            all_connections[total_connections].cur_total_data_len += all_packets[i].data_bytes;

            //update window size properties
            if (all_packets[i].window > all_connections[total_connections].max_win_size) {
                all_connections[total_connections].max_win_size = all_packets[i].window;

            } else if (all_packets[i].window < all_connections[total_connections].min_win_size) {
                all_connections[total_connections].min_win_size = all_packets[i].window;
            }

            all_connections[total_connections].sum_win_size += all_packets[i].window;

            total_connections++;
        }

    }

}

void print_connections() {
    printf("B) Connections' details:\n\n");
    
    int i;
    for (i = 0; i < total_connections; i++) {
        printf("Connection %d:\n", i+1);

        printf("Source Address: %s\n", all_connections[i].ip_src);
        printf("Destination Address: %s\n", all_connections[i].ip_dst);

        printf("Source Port: %d\n", all_connections[i].port_src);
        printf("Destination Port: %d\n", all_connections[i].port_dst);

        printf("Status: S%dF%d\n", all_connections[i].syn_count, all_connections[i].fin_count);

        //check if connection is complete (ie. at least one SYN and one FIN)
        if (all_connections[i].syn_count > 0 && all_connections[i].fin_count > 0) {
            printf("Start time: %.3f\n", atof(timestamp_string(all_connections[i].start_time)));
            printf("End time: %.3f\n", atof(timestamp_string(all_connections[i].end_time)));
            printf("Duration: %.3f\n", atof(timestamp_string(timeval_subtract(all_connections[i].end_time, all_connections[i].start_time))));

            printf("Number of packets sent from Source to Destination: %d\n", all_connections[i].num_packet_src);
            printf("Number of packets sent from Destination to Source: %d\n", all_connections[i].num_packet_dst);
            printf("Total number of packets: %d\n", all_connections[i].num_total_packets);

            printf("Number of data bytes sent from Source to Destination: %d\n", all_connections[i].cur_data_len_src);
            printf("Number of data bytes sent from Destination to Source: %d\n", all_connections[i].cur_data_len_dst);
            printf("Total number of data bytes: %d\n", all_connections[i].cur_total_data_len);

        }

        printf("END\n");
        printf("+++++++++++++++++++++++++\n");
    }

}

void print_general_info() {
    printf("C) General:\n\n");

    int i;
    int complete = 0;
    int reset = 0;
    int open = 0;

    for (i = 0; i < total_connections; i++) {
        //get number of complete connections
        if (all_connections[i].syn_count > 0 && all_connections[i].fin_count > 0) {
            complete++;
        }

        //get number of reset connections
        if (all_connections[i].rst_count > 0) {
            reset++;
        }

        //get number of open connections
        if (all_connections[i].syn_count > 0 && all_connections[i].fin_count == 0) {
            open++;
        }
    }
    printf("Total number of complete TCP connections: %d\n", complete);
    printf("Number of reset TCP connections: %d\n", reset);
    printf("Number of TCP connections that were still open when the trace capture ended: %d\n", open);


}

void print_numerical_info() {
    printf("D) Complete TCP connections:\n\n");

    int i;
    double min_time, max_time, sum_duration = 0;
    double min_rtt, max_rtt, sum_rtt;
    int min_packets, max_packets;
    int min_window, max_window, sum_window = 0;

    int complete_connections = 0, complete_packets = 0;

    //starting values are those of first connection
    min_time = all_connections[0].duration;
    max_time = all_connections[0].duration;

    min_rtt = all_connections[0].min_rtt;
    max_rtt = all_connections[0].max_rtt;

    min_packets = all_connections[0].num_total_packets;
    max_packets = all_connections[0].num_total_packets;

    min_window = all_connections[0].min_win_size;
    max_window = all_connections[0].max_win_size;

    for (i = 0; i < total_connections; i++) {
      
        if (all_connections[i].syn_count > 0 && all_connections[i].fin_count > 0) {
            //time durations
            if (all_connections[i].duration < min_time) { min_time = all_connections[i].duration; }

            if (all_connections[i].duration > max_time) { max_time = all_connections[i].duration; }

            sum_duration += all_connections[i].duration;

            //RTT
            if (all_connections[i].min_rtt < min_rtt) { min_rtt = all_connections[i].min_rtt; }

            if (all_connections[i].max_rtt > max_rtt) { max_rtt = all_connections[i].max_rtt; }

            sum_rtt += all_connections[i].sum_rtt;

            //# of packets
            if (all_connections[i].num_total_packets < min_packets) { min_packets = all_connections[i].num_total_packets; }

            if (all_connections[i].num_total_packets > max_packets) { max_packets = all_connections[i].num_total_packets; }

            //window size
            if (all_connections[i].min_win_size < min_window) { min_window = all_connections[i].min_win_size; }

            if (all_connections[i].max_win_size > max_window) { max_window = all_connections[i].max_win_size; }

            sum_window += all_connections[i].sum_win_size;

            complete_connections++;
            complete_packets += all_connections[i].num_total_packets;
        }
    }

    printf("Minimum time durations: %.3f\n", min_time);
    printf("Mean time durations: %.3f\n", sum_duration/complete_connections);
    printf("Maximum time durations: %.3f\n", max_time);

    printf("\n");

    printf("Minimum RTT values including both send/received: %.3f\n", min_rtt);
    printf("Mean RTT values including both send/received: %.3f\n", sum_rtt/complete_connections);
    printf("Maximum RTT values including both send/received: %.3f\n", max_rtt);

    printf("\n");

    printf("Minimum number of packets including both send/received: %d\n", min_packets);
    printf("Mean number of packets including both send/received: %d\n", complete_packets/complete_connections);
    printf("Maximum number of packets including both send/received: %d\n", max_packets);

    printf("\n");

    printf("Minimum receive window sizes including both send/received: %d\n", min_window);
    printf("Mean receive window sizes including both send/received: %d\n", sum_window/complete_packets);
    printf("Maximum receive window sizes including both send/received: %d\n", max_window);
}


int main(int argc, char *argv[]) {
    if (argc != 2) {
        printf("Error: Missing argument [trace_file]\n");
        exit(1);
    }

    pcap_t *pcap;
    struct pcap_pkthdr header;
    char errbuf[PCAP_ERRBUF_SIZE];
    const unsigned char *packet;
    pcap = pcap_open_offline(argv[1], errbuf);

    //bad input or file not found
    if (pcap == NULL) {
        printf("Couldn't open pcap file %s.\n", errbuf);
        exit(1);
    }

    //extract all the packets from trace file
    while ((packet = pcap_next(pcap, &header)) != NULL) {
        parse_packet(packet, header.ts, header.caplen);
        total_packets++;
    }

    check_connections();

    printf("A) Total number of connections = %d\n", total_connections);
    printf("-------------------------\n");

    print_connections();
    printf("-------------------------\n");

    print_general_info();
    printf("-------------------------\n");

    print_numerical_info();
    printf("-------------------------\n");

    return 0;
}

const char *timestamp_string(struct timeval ts) {
	static char timestamp_string_buf[256];

	sprintf(timestamp_string_buf, "%d.%06d",
		(int) ts.tv_sec, (int) ts.tv_usec);

	return timestamp_string_buf;
}


struct timeval timeval_subtract (struct timeval x, struct timeval y) {
    struct timeval result;
    //consider carried value in subtraction
    if (x.tv_usec < y.tv_usec) {
        int nsec = (y.tv_usec - x.tv_usec) / 1000000 + 1;
        y.tv_usec -= 1000000 * nsec;
        y.tv_sec += nsec;
    }
    if (x.tv_usec - y.tv_usec > 1000000) {
        int nsec = (x.tv_usec - y.tv_usec) / 1000000;
        y.tv_usec += 1000000 * nsec;
        y.tv_sec -= nsec;
    }

    result.tv_sec = x.tv_sec - y.tv_sec;
    result.tv_usec = x.tv_usec - y.tv_usec;

    return result;
}
