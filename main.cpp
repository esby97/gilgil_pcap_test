#include <pcap.h>
#include <stdio.h>
#include <stdint.h>

#define ETHERNET_TYPE_IP 0x0800
#define IP_PROTOCOL_TCP 6

typedef struct{
    const u_char Dmac[6];
    const u_char Smac[6];
    const u_short type;
}Ethernet;

typedef struct{
    const u_int8_t IHL;
    const u_char service;
    const u_short total_length;
    const u_char dummy2[5];
    const u_int8_t protocol;
    const u_char dummy3[2];
    const uint8_t source_address[4];
    const uint8_t destination_address[4];

}IP;

typedef struct{
    const u_short source_port;
    const u_short destination_port;
    const u_char dummy[8];
    const uint8_t Hlen;
    const u_char dummy2[7];
}TCP;

uint16_t my_ntohs(uint16_t n) { // network byte order to host byte order (2 byte)
    return (n & 0xff00) >> 8 | (n & 0xff) << 8 ;
}

uint32_t my_ntohl(uint32_t n) { // network byte order to host byte order (4 byte)
    return
        (n & 0xff000000) >> 24 |
        (n & 0x00ff0000) >> 8 |
        (n & 0x0000ff00) << 8 |
        (n & 0x000000ff) << 24;
}

void print_mac(const u_char* packet) {
    printf("%02X:%02X:%02X:%02X:%02X:%02X\n", packet[0], packet[1], packet[2], packet[3], packet[4], packet[5]);
}

void print_ip(const uint8_t* ip) {
    printf("%u.%u.%u.%u\n", ip[0], ip[1], ip[2], ip[3]);
}

void print_port(const u_short port) {
    printf("%d\n", (port & 0xff00) >> 8  | (port & 0x00ff) << 8);
}

void print_star(){
    printf("----------------------------------------\n");
}

void usage() {
  printf("syntax: pcap_test <interface>\n");
  printf("sample: pcap_test wlan0\n");
}

int main(int argc, char* argv[]) {
  if (argc != 2) {
    usage();
    return -1;
  }

  char* dev = argv[1];
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
  if (handle == NULL) {
    fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
    return -1;
  }

  while (true) {
    struct pcap_pkthdr* header;
    const u_char* packet;
    int res = pcap_next_ex(handle, &header, &packet);
    if (res == 0) continue;
    if (res == -1 || res == -2) break;

    int pointer = 0; // for tracing the offset.
    const Ethernet* ethernet = reinterpret_cast<const Ethernet *>(packet + pointer);
    print_star();
    printf("Dmac : ");
    print_mac(ethernet->Dmac);
    printf("Smac : ");
    print_mac(ethernet->Smac);
    if(ethernet->type != my_ntohs(ETHERNET_TYPE_IP)){
        printf("It isn't IPv4\n");
        continue;
    }

    pointer += 14;
    const IP* ip = reinterpret_cast<const IP *>(packet + pointer);
    printf("Sip : ");
    print_ip(ip->source_address);
    printf("Dip : ");
    print_ip(ip->destination_address);
    if(ip->protocol != IP_PROTOCOL_TCP){
        printf("It isn't TCP\n");
        continue;
    }

    pointer += (ip->IHL & 0x0f) * 4;
    const TCP* tcp = reinterpret_cast<const TCP *>(packet + pointer);
    printf("Sport : ");
    print_port(tcp->source_port);
    printf("Dport : ");
    print_port(tcp->destination_port);
    int tcp_segment_len = my_ntohs(ip->total_length) - (ip->IHL & 0x0f) * 4 - ((tcp->Hlen & 0xf0) >> 4) * 4;
    if(tcp_segment_len) pointer += (tcp->Hlen & 0xf0) >> 2;
    for(int i=0;i<tcp_segment_len && i<10;i++){
        printf("%.1X ", *(packet + pointer+i));
    }
    putchar('\n');
  }
  pcap_close(handle);
  return 0;
}
