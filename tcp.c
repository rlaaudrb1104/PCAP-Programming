// gcc -o tcp tcp.c -lpcap
// sudo ./tcp

#include <stdio.h>
#include <pcap.h>
#include <netinet/ether.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#define MAX_PAYLOAD_PRINT 1028
/* Ethernet header */
struct ethheader {
    u_char  ether_dhost[6]; /* destination host address */
    u_char  ether_shost[6]; /* source host address */
    u_short ether_type;     /* protocol type (IP, ARP, RARP, etc) */
};
  
/* IP Header */
struct ipheader {
    unsigned char      iph_ihl:4, //IP header length
                        iph_ver:4; //IP version
    unsigned char      iph_tos; //Type of service
    unsigned short int iph_len; //IP Packet length (data + header)
    unsigned short int iph_ident; //Identification
    unsigned short int iph_flag:3, //Fragmentation flags
                        iph_offset:13; //Flags offset
    unsigned char      iph_ttl; //Time to Live
    unsigned char      iph_protocol; //Protocol type
    unsigned short int iph_chksum; //IP datagram checksum
    struct  in_addr    iph_sourceip; //Source IP address
    struct  in_addr    iph_destip;   //Destination IP address
};

/* TCP Header */
struct tcpheader {
    u_short tcp_sport;
    u_short tcp_dport;
    u_int   tcp_seq;
    u_int   tcp_ack;
    u_char  tcp_offx2;
    u_char  tcp_flags;
#define TH_FIN  0x01
#define TH_SYN  0x02
#define TH_RST  0x04
#define TH_PUSH 0x08
#define TH_ACK  0x10
#define TH_URG  0x20
#define TH_ECE  0x40
#define TH_CWR  0x80
#define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
    u_short tcp_win;
    u_short tcp_sum;
    u_short tcp_urp;
};

void packet_capture(u_char *args, const struct pcap_pkthdr *header, const u_char *packet){

    struct ethheader *eth = (struct ethheader *)packet;
    struct ipheader *ip = (struct ipheader *)(packet + sizeof(struct ethheader));
    int ip_header_length = ip->iph_ihl * 4;
    struct tcpheader *tcp = (struct tcpheader *)(packet + sizeof(struct ethheader) + ip_header_length);

    int tcp_header_length = ((tcp->tcp_offx2 & 0xF0) >> 4) * 4;
    int total_ip_length = ntohs(ip->iph_len);
    int payload_length = total_ip_length - (ip_header_length + tcp_header_length);

    const u_char *payload = packet + sizeof(struct ethheader) + ip_header_length + tcp_header_length;

    if (ip->iph_protocol != IPPROTO_TCP) {
        return;
    }
    
    printf("-----------------------------------------------\n");
    printf("            SRC          |         DST         \n");
    printf("[MAC]: %s --> ", ether_ntoa((struct ether_addr *)eth->ether_shost));
    printf(" %s \n", ether_ntoa((struct ether_addr *)eth->ether_dhost));
    printf("[IP]: %s --> ", inet_ntoa(ip->iph_sourceip)); 
    printf(" %s \n", inet_ntoa(ip->iph_destip));
    printf("[Port]: %d --> ", ntohs(tcp->tcp_sport));
    printf(" %d \n", ntohs(tcp->tcp_dport));
    printf("-----------------------------------------------\n");

    int print_length = payload_length > MAX_PAYLOAD_PRINT ? MAX_PAYLOAD_PRINT : payload_length;
    printf("[Payload] (%d bytes):\n", print_length);

    for (int i = 0; i < print_length; i++) {
        if (isprint(payload[i]))
            printf("%c", payload[i]);
        else
            printf(".");
    }

    if (payload_length > MAX_PAYLOAD_PRINT) {
        printf("[more]...\n");
    } else {
        printf("\n");
    }

    printf("\n");
}

int main(){
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];

    handle = pcap_open_live("eth0", BUFSIZ, 1, 1000, errbuf);

    pcap_loop(handle, 0, packet_capture, NULL);

    pcap_close(handle);

    return 0;
}