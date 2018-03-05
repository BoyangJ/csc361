/*------------------------------
* Name: Boyang Jiao
* UvicID: V00800928
* Date: July 22, 2016
*
* tracer.c
* Description: Reads and analyses a traceroute trace file.
* CSC 361
* Instructor: Kui Wu
-------------------------------*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <time.h>
#include <math.h>

#include <sys/cdefs.h>
#include <sys/types.h>

#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <net/if.h>
#include <netinet/if_ether.h>
#include <netinet/tcp.h>
#include <netinet/ip_icmp.h>
#include <pcap/pcap.h>

#include <arpa/inet.h>

#include "util.c"

#define DEBUG 0
#define MAX_STR_LEN 1024

#define CHECK_BIT(var,pos) ((var) & (1<<(pos)))     //checks whether bit at pos is 1

int total_routers = 0;
struct router all_routers[1024];

int total_protocols = 0;
int protocols[128];

int total_outgoing = 0;
struct packet_time all_outgoing[1024];
int total_incoming = 0;
struct packet_time all_incoming[1024];

char *src_ip;       //source ip
char *dst_ip;       //ultimate destination ip
int first_id = 0;       //ID number of first packet sent by traceroute

int fragments = 0;
int last_frag;

//function prototypes
const char *timestamp_string(struct timeval ts);
struct timeval timeval_subtract (struct timeval x, struct timeval y);

void add_protocol(int protocol_number);
void add_router(const unsigned char *packet, struct ip *ip, struct timeval ts);
void add_outgoing(struct ip *ip, unsigned short id, uint16_t port, struct timeval ts);
void add_incoming(struct ip *ip, unsigned short id, uint16_t port, struct timeval ts);

int dump_packet(const unsigned char *packet, unsigned int capture_len, struct timeval ts);
int analyze_packet(struct ip *ip, const unsigned char* packet, struct timeval ts);
void calculate_RTTs();
void print_stats();

void print_debug();
int read_next = 0;          //used to force program to read packet fragments

/***************/

void add_protocol(int protocol_number) {
    int new_protocol = 1;
    int i = 0;
    for (i = 0; i < total_protocols; i++) {
        if (protocols[i] == protocol_number) { new_protocol = 0; }
    }
    if (new_protocol) {
        protocols[total_protocols] = protocol_number;
        total_protocols++;
    }
}

void add_router(const unsigned char *packet, struct ip *ip, struct timeval ts) {
    char *addr = inet_ntoa(ip->ip_src);

    int new_router = 1;
    int i = 0;
    //do not add if this router is already in the list
    for (i = 0; i < total_routers; i++) {
        if (!strcmp(addr, all_routers[i].ip)) { new_router = 0; }
    }

    if (new_router) {
        all_routers[total_routers].ip = (char*) malloc(100);
        strcpy(all_routers[total_routers].ip, addr);

        total_routers++;
    }

}

void add_outgoing(struct ip *ip, unsigned short id, uint16_t port, struct timeval ts) {

    char *addr = inet_ntoa(ip->ip_dst);
    all_outgoing[total_outgoing].ip = (char*) malloc(100);
    strcpy(all_outgoing[total_outgoing].ip, addr);
    
    all_outgoing[total_outgoing].time = ts;
    all_outgoing[total_outgoing].src_port = port;
    all_outgoing[total_outgoing].id = id;

    total_outgoing++;

}

void add_incoming(struct ip *ip, unsigned short id, uint16_t port, struct timeval ts) {

    char *addr = inet_ntoa(ip->ip_src);
    all_incoming[total_incoming].ip = (char*) malloc(100);
    strcpy(all_incoming[total_incoming].ip, addr);

    all_incoming[total_incoming].time = ts;
    all_incoming[total_incoming].src_port = port;
    all_incoming[total_incoming].id = id;

    total_incoming++;

}

int analyze_packet(struct ip *ip, const unsigned char* packet, struct timeval ts) {
    struct icmp *icmp, *icmp2;
    struct udphdr *udp;
    uint16_t port;
    unsigned short temp, id, offset;
    int mf;

    //get id of packet
    temp = ip->ip_id;
    id = (temp>>8) | (temp<<8);

    /*** ICMP PACKET ***/
    if (ip->ip_p == 1) {
        icmp = (struct icmp*) packet;      //icmp now points to start of icmp header

        //skip icmp header        
        packet += 8;

        //get ip header
        struct ip* ip2;
        ip2 = (struct ip*) packet;       //ip2 now points to start of IP header
        unsigned int ip2_header_length = ip2->ip_hl * 4;

        //skip ip header
        packet += ip2_header_length;
        
        udp = (struct udphdr*) packet;      //udp now points to start of udp header
        //only consider port number if packet is an icmp reply to a udp packet
        char *addr = inet_ntoa(ip->ip_dst);
        if (ip2->ip_p == 17) {
            port = ntohs(udp->source); 
        } else {
            port = 0;
        }

        icmp2 = (struct icmp*) packet;      //icmp2 now points to start of icmp header

        //add protocol to list
        add_protocol(ip->ip_p);

        //if packet timed out
        if (icmp->icmp_type == 11) {
            //printf("TIMEOUT PACKET RECEIVED, TTL WAS %d\n", ip->ip_ttl);

            //add intermediate router to list
            add_router(packet, ip, ts);

            //record incoming packet time
            add_incoming(ip, icmp2->icmp_seq, port, ts);

        //if first packet sent in the traceroute
        } else if ( (icmp->icmp_type == 8) && (ip->ip_ttl == 1) && (first_id == 0) ) {

            //record src and dst IP addresses
            char *addr = inet_ntoa(ip->ip_src);
            src_ip = (char*) malloc(100);
            strcpy(src_ip, addr);

            addr = inet_ntoa(ip->ip_dst);
            dst_ip = (char*) malloc(100);
            strcpy(dst_ip, addr);

            //record time packet was sent
            add_outgoing(ip, icmp->icmp_seq, port, ts);

            //set id of first packet
            first_id = id;

            //get MF flag value
            mf = (ip->ip_off & 0x0020) >> 5;

            if (mf == 1) {
                fragments++;
            }
        
        //if packet is a fragment of the first packet
        } else if (id == first_id) {

            //get MF flag value
            mf = (ip->ip_off & 0x0020) >> 5;
            fragments++;

            //get fragment offset
            temp = ip->ip_off & 0xFF1F;
            offset = (temp>>8) | (temp<<8);

            //calculate offset if last fragment
            if (mf == 0) {
                last_frag = offset * 8;
            }

            //record time packet fragment was sent
            add_outgoing(ip, icmp->icmp_seq, port, ts);

        //if packet is an outgoing packet
        } else if ( icmp->icmp_type == 8 ) {

            //record time packet was sent
            add_outgoing(ip, icmp->icmp_seq, port, ts);

        //if packet reaches destination
        } else if ( (icmp->icmp_type == 0) | (icmp->icmp_type == 3) ) {

            add_router(packet, ip, ts);

            //record incoming packet time
            add_incoming(ip, icmp->icmp_seq, port, ts);
            return 0;

        }

    /*** UDP PACKET ***/
    } else if (ip->ip_p == 17) {
        
        uint16_t dst_port;

        udp = (struct udphdr*) packet;      //udp now points to start of udp header
        port = ntohs(udp->source);
        dst_port = ntohs(udp->dest);

        //restrictions: for UDP traceroute datagrams,
        //dst_port must be between 33434 and 33534.
        if ( ((dst_port >= 33434) && (dst_port <= 33534)) || read_next ) {

            //add protocol to list
            add_protocol(ip->ip_p);

            //if first packet sent in the traceroute
            if ( (ip->ip_ttl == 1) && (first_id == 0) ) {

                //record src and dst IP addresses
                char *addr = inet_ntoa(ip->ip_src);
                src_ip = (char*) malloc(100);
                strcpy(src_ip, addr);

                addr = inet_ntoa(ip->ip_dst);
                dst_ip = (char*) malloc(100);
                strcpy(dst_ip, addr);

                //record time packet was sent
                add_outgoing(ip, -1, port, ts);

                //set id of first packet
                first_id = id;

                //get MF flag value
                mf = (ip->ip_off & 0x0020) >> 5;

                if (mf == 1) {
                    read_next = 1;
                    fragments++;
                }       

            //if packet is a fragment of the first packet
            } else if (id == first_id) {

                //get MF flag value
                mf = (ip->ip_off & 0x0020) >> 5;
                fragments++;

                //get fragment offset
                temp = ip->ip_off & 0xFF1F;
                offset = (temp>>8) | (temp<<8);

                //calculate offset if last fragment
                if (mf == 0) {
                    last_frag = offset * 8;
                    read_next = 0;
                }

                //record time packet fragment was sent
                add_outgoing(ip, -1, port, ts);

            //packet is outgoing packet (not first)
            } else {

                //get MF flag value
                mf = (ip->ip_off & 0x0020) >> 5;

                if (mf == 1) {
                    read_next = 1;
                } else {
                    read_next = 0;
                }

                //record time packet fragment was sent
                add_outgoing(ip, -1, port, ts);

            }
        } 
    } 

    return 0;
}


int dump_packet(const unsigned char *packet, unsigned int capture_len, struct timeval ts) {
    struct ip *ip;
    unsigned int ip_header_length;

    //skip the ethernet header (14 bytes)
    packet += sizeof(struct ether_header);
    capture_len -= sizeof(struct ether_header);

    //get ip header
    ip = (struct ip*) packet;       //ip now points to start of IP header
    ip_header_length = ip->ip_hl * 4;

    //skip ip header
    packet += ip_header_length;
    capture_len -= ip_header_length;

    //analyze contents of packet
    if (analyze_packet(ip, packet, ts)) {
        return 1;
    }

    return 0;

}

void calculate_RTTs() {
    int i, j = 0;
    //find all timestamp pairings
    for (i = 0; i < total_outgoing; i++) {
        for (j = 0; j < total_incoming; j++) {

            if ( ( (all_outgoing[i].id == all_incoming[j].id) && all_outgoing[i].id != 0 ) || 
                    ( (all_outgoing[i].src_port == all_incoming[j].src_port) && all_outgoing[i].src_port != 0) ) {

                int r = 0;
                for (r = 0; r < total_routers; r++) {
                    if (!strcmp(all_incoming[j].ip, all_routers[r].ip)) {

                        double diff = atof(timestamp_string(timeval_subtract(all_incoming[j].time, all_outgoing[i].time)));

                        all_routers[r].RTT[all_routers[r].num_connections] = diff;
                        all_routers[r].num_connections++;
                    } //if
                } //for

            } //if

        } //for
    } //for

    //calculate average RTT for each router
    for (i = 0; i < total_routers; i++) {
        for (j = 0; j < all_routers[i].num_connections; j++) {
            all_routers[i].RTT_avg += all_routers[i].RTT[j];
        }

        all_routers[i].RTT_avg = all_routers[i].RTT_avg / all_routers[i].num_connections;
        all_routers[i].RTT_avg *= 1000;
    }


    //calculate sd RTT for each router
    for (i = 0; i < total_routers; i++) {
        double sd = 0;
        for (j = 0; j < all_routers[i].num_connections; j++) {
            double diff = all_routers[i].RTT_avg - (all_routers[i].RTT[j]*1000);
            diff = diff * diff;
            sd += diff;
        }

        sd = sd / all_routers[i].num_connections;
        sd = sqrt(sd);

        all_routers[i].RTT_sd = sd;
    }

}

void print_stats() {
    /*** IP ADDRESSES 0F SOURCE AND DESTINATION ***/
    printf("The IP address of the source node: %s\n", src_ip);
    printf("The IP address of the ultimate destination node: %s\n", dst_ip);

    /*** IP ADDRESSES OF THE INTERMEDIATE NODES ***/
    printf("The IP addresses of the intermediate destination nodes:\n");

    int i = 0;
    int skip = 0;
    for (i = 0; i < total_routers; i++) {
        //don't include ultimate destination
        if (strcmp(all_routers[i].ip, dst_ip)) {
            printf("\trouter %d: %s\n", i+1-skip, all_routers[i].ip);
        } else {
            skip = 1;
        }
    }

    /*** PROTOCOLS ***/
    printf("\n");
    printf("The values in the protocol field of IP headers:\n");

    char *proto_name = malloc(5);
    for (i = 0; i < total_protocols; i++) {
        switch (protocols[i]) {
            case 1:
                strcpy(proto_name, "ICMP");
                break;
            case 17:
                strcpy(proto_name, "UDP");
                break;
        }
        printf("\t%d: %s\n", protocols[i], proto_name);
        
    }
    free(proto_name);

    /*** ORIGINAL DATAGRAM FRAGMENTS ***/
    printf("\n");
    printf("The number of fragments created from the original datagram is: %d\n", fragments);
    printf("The offset of the last fragment is: %d\n", last_frag);

    /*** RTT STATS ***/
    printf("\n");
    int dest_index = -1;

    for (i = 0; i < total_routers; i++) {
        //Print the ultimate destination last
        if (strcmp(all_routers[i].ip, dst_ip)) {
            printf("The avg RTT between %s and %s is: %.2f ms, the s.d. is: %.2f ms\n", src_ip, all_routers[i].ip, all_routers[i].RTT_avg, all_routers[i].RTT_sd);
        } else {
            dest_index = i;
        }
    }

    //print ultimate destination info
    if (dest_index != -1) {
        printf("The avg RTT between %s and %s is: %.2f ms, the s.d. is: %.2f ms\n", src_ip, all_routers[dest_index].ip, all_routers[dest_index].RTT_avg, all_routers[dest_index].RTT_sd);
    }
}

void print_debug() {
    int i, j = 0;
    for (i = 0; i < total_outgoing; i++) {
        printf("outgoing time %d:\n", i);
        printf("ip = %s\n", all_outgoing[i].ip);
        printf("port = %d\n", all_outgoing[i].src_port);
        printf("id = %d\n", all_outgoing[i].id);
        printf("time = %s\n", timestamp_string(all_outgoing[i].time));
        printf("\n");

    }

    for (i = 0; i < total_incoming; i++) {
        printf("incoming time %d:\n", i);
        printf("ip = %s\n", all_incoming[i].ip);
        printf("port = %d\n", all_incoming[i].src_port);
        printf("id = %d\n", all_incoming[i].id);
        printf("time = %s\n", timestamp_string(all_incoming[i].time));
        printf("\n");

    }

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
        if (dump_packet(packet, header.caplen, header.ts)) {
            break;
        }
        
    }
    //print_debug();

    calculate_RTTs();

    print_stats();

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
