#include <stdio.h>
#include <pcap.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>

#define ETH_ALEN 6

#pragma pack(push, 1)
typedef struct ip_hdr {
    unsigned char ip_hl : 4;
    unsigned char ip_v : 4; 
    unsigned char ip_tos;
    unsigned short ip_len;
    unsigned short ip_id;
    unsigned short ip_off;
    unsigned char ip_ttl; 
    unsigned char ip_p;  
    unsigned short ip_sum;
    unsigned char ip_src[4]; 
    unsigned char ip_dst[4];  
} IPV4_HDR;

typedef struct ethernet_hdr {
    unsigned char h_source[ETH_ALEN];
    unsigned char h_dest[ETH_ALEN];
    unsigned short h_proto;
} ETHERNET_HDR;

typedef struct _TCP_HDR {
    unsigned short source_port;
    unsigned short dest_port;
    unsigned int sequence_number;
    unsigned int ack_number;
    unsigned char reserved : 4;
    unsigned char data_offset : 4;
    unsigned short flags;
    unsigned short window;
    unsigned short checksum;
    unsigned short urgent_pointer;
} TCP_HDR;

typedef struct _tcp_packet {
    unsigned char data[];
} TCP_DATA;

typedef struct ipv4_packet {
    ETHERNET_HDR eth_hdr;
    IPV4_HDR ip_hdr;
    TCP_HDR tcp_hdr;
    TCP_DATA tcp_data;
} TCP_PACKET;

#pragma pack(pop)
int bytes;
void packet_handler(u_char* user_data, const struct pcap_pkthdr* pkthdr, const u_char* packet) {

    TCP_PACKET* packet_header = (TCP_PACKET*)(packet);

    if (packet_header->ip_hdr.ip_p == IPPROTO_TCP) {
        printf("-------------------------TCP------------------------\n");
        printf("Ethernet dst mac: %x.%x.%x.%x.%x.%x\n", packet_header->eth_hdr.h_dest[0], packet_header->eth_hdr.h_dest[1], packet_header->eth_hdr.h_dest[2], packet_header->eth_hdr.h_dest[3], packet_header->eth_hdr.h_dest[4], packet_header->eth_hdr.h_dest[5]);
        printf("Ethernet src mac: %x.%x.%x.%x.%x.%x\n\n", packet_header->eth_hdr.h_source[0], packet_header->eth_hdr.h_source[1], packet_header->eth_hdr.h_source[2], packet_header->eth_hdr.h_source[3], packet_header->eth_hdr.h_source[4], packet_header->eth_hdr.h_source[5]);
        printf("Src ip: %d.%d.%d.%d\n", packet_header->ip_hdr.ip_src[0], packet_header->ip_hdr.ip_src[1], packet_header->ip_hdr.ip_src[2], packet_header->ip_hdr.ip_src[3]);
        printf("Dst ip: %d.%d.%d.%d\n\n", packet_header->ip_hdr.ip_dst[0], packet_header->ip_hdr.ip_dst[1], packet_header->ip_hdr.ip_dst[2], packet_header->ip_hdr.ip_dst[3]);
        printf("TCP src port: %d\n", ntohs(packet_header->tcp_hdr.source_port));
        printf("TCP dst port: %d\n", ntohs(packet_header->tcp_hdr.dest_port));

        printf("\nPacket data (%d byte):\n", bytes);
        for (int i = 0; i < bytes  && packet_header->tcp_data.data[i]!='\0'; i++) {
            printf("%02X ", packet_header->tcp_data.data[i]);

            if ((i + 1) % 8 == 0) printf(" ");
            if ((i + 1) % 16 == 0) printf("\n");
        }

        printf("\n----------------------------------------------------\n\n");
    }
}

int main() {

    pcap_t* handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    int timeout_limit = 1000;
    int c=1;
    pcap_if_t* alldevs;
    pcap_if_t* d;

    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
        return 1;
    }

    for (d = alldevs; d != NULL; d = d->next) {
        printf("%d. %s ", c, d->name);
        if (d->description) printf("(%s)\n", d->description);
        else printf(" (No description available)\n");
        c++;
    }

    printf("\n\nChoice interface network: ");
    scanf("%d", &c);

    printf("Print data len: ");
    scanf("%d", &bytes);

    d = alldevs;
    for (int i = 1; i < c; i++) {
        d = d->next;
    }
    char* device = d->name;

    if (!device) {
        fprintf(stderr, "Error finding device: %s\n", errbuf);
        return 1;
    }

    handle = pcap_open_live(device, BUFSIZ, 1, timeout_limit, errbuf);
    if (!handle) {
        fprintf(stderr, "Could not open device %s: %s\n", device, errbuf);
        return 2;
    }

    pcap_loop(handle, 0, packet_handler, NULL);

    pcap_close(handle);
    pcap_freealldevs(alldevs);
    return 0;
}
