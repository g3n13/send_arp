#include <libnet.h>
#include <stdint.h>
#include <stdio.h>
#include <netinet/in.h>
#include <libnet/libnet-types.h>
#include <libnet/libnet-macros.h>
#include <libnet/libnet-headers.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>

#define SIZE_ETHERNET 14

void usage()
{
  printf("syntax: send_arp <interface> <sender IP> <target IP>\n");
  printf("sample: send_arp wlan0 192.168.10.2 192.168.10.1\n");
}

int main(int argc, char* argv[])
{
	int s, i;
	struct ifreq ifrq;
	
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


	//get sender's MAC
	
	



}
