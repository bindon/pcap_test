#include <pcap.h>
#include <stdio.h>
#include <stdint.h>
#include <arpa/inet.h>

#define ETHERTYPE_IP  0x0800
#define ETHERTYPE_ARP 0x0806

typedef struct _ethernetHeader {
  uint8_t destinationMac[6];
  uint8_t sourceMac[6];
  uint16_t type;
} ethernetHeader;

typedef struct _ipHeader {
#if BYTE_ORDER == LITTLE_ENDIAN
  uint8_t  headerLength:4, 
	   version:4;
#elif BYTE_ORDER == BIG_ENDIAN
  uint8_t  version:4,
           headerLength:4; 
#endif
  uint8_t  typeOfService;
  uint16_t totalLength;
  uint16_t id;
  uint16_t offset;
  uint8_t  timeToLive;
  uint8_t  protocol;
  uint16_t checksum;
  uint8_t  sourceIp[6];
  uint8_t  destinationIp[6];
} ipHeader;

typedef struct _tcpHeader {
  uint16_t sourcePort;
  uint16_t destinationPort;
  uint32_t seqNumber;
  uint32_t ackNumber;
#if BYTE_ORDER == LITTLE_ENDIAN
  uint8_t  reserved:4, 
	   offset:4;
#elif BYTE_ORDER == BIG_ENDIAN
  uint8_t  offset:4, 
	   reserved:4;
#endif
  uint8_t  flags;
  uint16_t window;
  uint16_t checksum;
  uint16_t urgent;
} tcpHeader;

void printMacAddress(const char *prefix, u_char *startAddress) {
  printf("%s[%02x:%02x:%02x:%02x:%02x:%02x]\n", prefix, 
    startAddress[0], startAddress[1], startAddress[2],
    startAddress[3], startAddress[4], startAddress[5]);
}

void printIpAddress(const char *prefix, u_char *startAddress) {
  printf("%s[%d.%d.%d.%d]\n", prefix, 
    startAddress[0], startAddress[1], startAddress[2], startAddress[3]);
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
    fprintf(stderr, "couldn't open devicnetinet/if_ether.he %s: %s\n", dev, errbuf);
    return -1;
  }

  while (true) {
    struct pcap_pkthdr* header;
    const u_char* packet;
    int res = pcap_next_ex(handle, &header, &packet);
    if (res == 0) continue;
    if (res == -1 || res == -2) break;
    printf("%u bytes captured\n", header->caplen);
    printf("\n[Packet Parsing...]\n");
    printf("1. Ethernet Information\n");
    ethernetHeader *ethernetPacket = (ethernetHeader *)packet;
    printMacAddress("  - Dest MAC : ", ethernetPacket->destinationMac);
    printMacAddress("  - Src  MAC : ", ethernetPacket->sourceMac);
    printf("  - Type     : [%04x]\n",  ethernetPacket->type);

    ipHeader *ipPacket = NULL;
    tcpHeader *tcpPacket = NULL;

    switch(ntohs(ethernetPacket->type)) {
      case ETHERTYPE_IP:
	ipPacket = (ipHeader *)(packet + sizeof(ethernetHeader));
	printf("\n2. IP Information\n");
	printf("  - Version       : [IPv%d]\n", ipPacket->version);
	printf("  - Header Length : [%d]\n", ipPacket->headerLength << 2);
	printf("  - Time to Live  : [%d]\n", ipPacket->timeToLive);
	printf("  - Protocol      : [%x]\n", ipPacket->protocol);
	printIpAddress("  - Src  IP Addr  : ", ipPacket->sourceIp);
	printIpAddress("  - Dest IP Addr  : ", ipPacket->destinationIp);
	switch(ipPacket->protocol) {
	  case IPPROTO_TCP:
            printf("\n3. TCP Information\n");
            tcpPacket = (tcpHeader *)(packet + sizeof(ethernetHeader) + (ipPacket->headerLength << 2));
	    printf("  - Src  Port : [%d]\n", ntohs(tcpPacket->sourcePort));
	    printf("  - Dest Port : [%d]\n", ntohs(tcpPacket->destinationPort));
	    break;
          case IPPROTO_UDP:
            printf("UDP Packet is not Supported!\n");
	    break;
	}
	break;
      case ETHERTYPE_ARP:
	printf("ARP Packet is not Supported!\n");
	break;
      default:
	printf("Unsupported Packet\n");
    }
    printf("\n\n");
  }

  pcap_close(handle);
  return 0;
}
