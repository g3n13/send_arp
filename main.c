#include <libnet.h>
#include <netinet/in.h>
#include <libnet/libnet-types.h>
#include <libnet/libnet-macros.h>
#include <libnet/libnet-headers.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <stdint.h>
#include <stdio.h>

#define SIZE_ETHERNET 14

typedef struct arphdr
{
        uint16_t ar_hrd;
        uint16_t ar_pro;
        uint8_t ar_hln;
        uint8_t ar_pln;
        uint16_t ar_op;
        uint8_t sender_mac[6];
        uint8_t sender_ip[4];
        uint8_t target_mac[6];
        uint8_t target_ip[4];
}arphdr;

void usage()
{
  printf("syntax: send_arp <interface> <sender IP> <target IP>\n");
  printf("sample: send_arp wlan0 192.168.10.2 192.168.10.1\n");
}

void make_arp_pkt(arphdr* arp_pkt, uint8_t* s_mac, uint8_t* t_mac, int op)
{
	int i;
	arp_pkt->ar_hrd=htons(0x1);
	arp_pkt->ar_pro=htons(0x0800);
	arp_pkt->ar_hln=6;
	arp_pkt->ar_pln=4;
	arp_pkt->ar_op=htons(op);
	
	memcpy(arp_pkt->sender_mac, s_mac, 6*sizeof(uint8_t));
	
	if(t_mac!=NULL)
		memcpy(arp_pkt->target_mac, t_mac, 6*sizeof(uint8_t));
	else
		memset(arp_pkt->target_mac, 0, 6*sizeof(uint8_t));
}

void make_ether_pkt(libnet_ethernet_hdr* eth_pkt, uint8_t* dhost, uint8_t* shost, arphdr* arp_hdr)
{
	memcpy(eth_pkt->ether_dhost, dhost, 6*sizeof(uint8_t));
	memcpy(eth_pkt->ether_shost, shost, 6*sizeof(uint8_t));
	eth_pkt->ether_type=htons(0x0806);
	
	memcpy(eth_pkt+sizeof(struct libnet_ethernet_hdr), &arp_hdr, sizeof(struct arphdr));
}
		

int main(int argc, char* argv[])
{
	int s, i;
	struct ifreq ifrq;
	struct arphdr s_arphdr, t_arphdr;
	uint8_t* mymac=(uint8_t*)malloc(6*sizeof(uint8_t));
	uint8_t* s_mac=(uint8_t*)malloc(6*sizeof(uint8_t));
	uint8_t* t_mac=(uint8_t*)malloc(6*sizeof(uint8_t));
	
	if (argc != 4)
	{
		usage();
		return -1;
 	}
		
	s = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
	if (s<0)
	{
		printf("socket error\n");
		return -1;
	}
	
	strcpy(ifrq.ifr_name, argv[1]);
	if(ioctl(s, SIOCGIFHWADDR, &ifrq) < 0)		//MAC 주소를 가져와서 ifrq에 저장
	{
                printf("MAC error\n");
                return -1;
        }
	
	//my MAC address
	printf("My MAC address: ");
	for(i=0;i<6;i++)
	{
		if(i<5)
			printf("%02x:",(unsigned char)ifrq.ifr_addr.sa_data[i]);
		else
			printf("%02x\n",(unsigned char)ifrq.ifr_addr.sa_data[i]);
	}
	memcpy(mymac, ifrq.ifr_addr.sa_data, 6*sizeof(uint8_t));
	
	if(ioctl(s, SIOCGIFADDR, &ifrq) < 0)          //IP 주소를 가져와서 ifrq에 저장
        {
                printf("IP error\n");
                return -1;
        }

        //my IP address
        printf("My IP address: ");
	struct sockaddr_in *sin;
	char ipbuf[32];
	sin=(struct sockaddr_in*)&ifrq.ifr_addr;
	printf("%s\n",inet_ntop(AF_INET,&sin->sin_addr,ipbuf,sizeof(ipbuf)));


	//make sender's arp packet
	memset(t_mac, NULL, 6*sizeof(uint8_t));
	make_arp_pkt(&s_arphdr, mymac, t_mac, 1);
	inet_pton(AF_INET, argv[1], &s_arphdr.sender_ip);
	inet_pton(AF_INET, argv[2], &s_arphdr.target_ip);
	
	//make sender's ethernet packet
	struct libnet_ethernet_hdr s_ethpkt;
	int size;
	memset(t_mac, 255, 6*sizeof(uint8_t));
	make_ether_pkt(&s_ethpkt, t_mac, mymac, &s_arphdr);
	size=sizeof(struct libnet_ethernet_hdr)+sizeof(struct arphdr);
	uint8_t* packet=(uint8_t*)malloc(size*sizeof(uint8_t));
	memcpy(packet, &s_ethpkt, size*sizeof(uint8_t));

	//send packet	
  	char* dev = argv[1];
 	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if (handle == NULL) 
	{
    		fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
		return -1;
  	}
	if(pcap_sendpacket(handle, packet, size))
	{
		printf("Failed send packet\n");
		return -1;
	}







}
