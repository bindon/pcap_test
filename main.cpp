#include <pcap.h>
#include <stdio.h>

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
    printf("%u bytes captured\n", header->caplen);
    printf("\n[Packet Parsing...]\n");
    printf("1. Ethernet Information\n");
    printf("  - Dest MAC : [%02x:%02x:%02x:%02x:%02x:%02x]\n", 
      packet[0], packet[1], packet[2], packet[3], packet[4],  packet[5]);
    printf("  - Src  MAC : [%02x:%02x:%02x:%02x:%02x:%02x]\n", 
      packet[6], packet[7], packet[8], packet[9], packet[10], packet[11]);
    short type = (packet[12] << 8) | packet[13];
    printf("  - Type     : [%04x]\n", type);

    switch(type) {
      case 0x0800:
	printf("\n2. IP Information\n");
	printf("  - Version       : [IPv%d]\n", (packet[14] >> 4));
	printf("  - Header Length : [%d]\n", ((packet[14] & 0xF) << 2));
	printf("  - Time to Live  : [%d]\n", packet[22]);
	printf("  - Protocol      : [%x]\n", packet[23]);
	printf("  - Src  IP Addr  : [%d.%d.%d.%d]\n", 
          packet[26], packet[27], packet[28], packet[29]);
	printf("  - Dest IP Addr  : [%d.%d.%d.%d]\n", 
          packet[30], packet[31], packet[32], packet[33]);
	switch(packet[23]) {
	  case 0x06:
            printf("\n3. TCP Information\n");
	    printf("  - Src  Port : [%d]\n", ((packet[34] << 8) | packet[35]));
	    printf("  - Dest Port : [%d]\n", ((packet[36] << 8) | packet[37]));
	    break;
          case 0x11:
            printf("\n3. UDP Information\n");
	    printf("  - Src  Port : [%d]\n", ((packet[34] << 8) | packet[35]));
	    printf("  - Dest Port : [%d]\n", ((packet[36] << 8) | packet[37]));
	    break;
	}
	break;
      case 0x0806:
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
