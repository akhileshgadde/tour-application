#include "unp.h"
#include "hw_addrs.h"
#include <netpacket/packet.h>
#include <net/ethernet.h> 

#define MAX_ITEMS 50
#define ARP_PROTO 0x6849
#define ID_FIELD 0x2313
#define ARP_PATH "/tmp/arp8132"
struct cacheTable
{
	unsigned short htype;    /* Hardware Type           */
	char ipaddr[50];
	int sll_ifindex;
	unsigned char ha[6];
	int connfd;
}cache_table[50];

struct hwaddr {
    int             sll_ifindex;	 /* Interface number */
	char 			ipaddr[50];
    unsigned short  sll_hatype;	 	 /* Hardware type */
    unsigned char   sll_halen;		 /* Length of address */
    unsigned char   sll_addr[8];	 /* Physical layer address */
};

static int cacheCount;

struct arpheader
{
	unsigned short htype;    /* Hardware Type           */ 
    u_int16_t ptype;    	 /* Protocol Type           */ 
    u_char hlen;        	 /* Hardware Address Length */ 
    u_char plen;        	 /* Protocol Address Length */ 
    u_int16_t oper;     	 /* Operation Code          */ 
    unsigned char sha[6];    /* Sender hardware address */ 
    char spa[50];     		 /* Sender IP address       */ 
    unsigned char tha[6];    /* Target hardware address */ 
    char tpa[50];      		 /* Target IP address       */
    unsigned char id[2];
};

void getLocalInterface();
void listenSockets();
void addToCache(struct cacheTable *cache_table, struct cacheTable ct, int *cacheCount);
int updateCacheTable(char ipaddr[], unsigned char macaddr[]);
int checkCacheTable(char ipaddr[]);
void print_cacheTable();
void recvFromPF();
void recvFromUnix();
void sendFromPF(struct arpheader ah);
char* GetHostname(char ip[]);

int pfsockfd, listenfd, connfd;
//int errno = 1;
char vm_name[50];
struct sockaddr_un servaddr; 	//arp
struct sockaddr_un cliaddr; 	//tour
int main()
{
	getLocalInterface();
	pfsockfd = Socket(PF_PACKET, SOCK_RAW, htons(ARP_PROTO));

	listenfd = Socket(AF_LOCAL, SOCK_STREAM, 0);
	unlink(ARP_PATH);
	bzero(&servaddr, sizeof(servaddr));
	servaddr.sun_family = AF_LOCAL;
	strcpy(servaddr.sun_path, ARP_PATH);
	Bind(listenfd, (SA *)&servaddr, sizeof(servaddr));
	Listen(listenfd, LISTENQ);

	listenSockets();
}


void listenSockets()
{
	int maxfdp1, i;
	int clilen = sizeof(cliaddr);
	fd_set rset;

	for(;;)
	{
		//printf("In select\n\n\n\n\n\n\n\n");
		FD_ZERO(&rset);
		FD_SET(pfsockfd, &rset);
		FD_SET(listenfd, &rset);

		maxfdp1 = max(pfsockfd, listenfd) + 1;
		//printf("maxfdp1: %d\n",maxfdp1);

		if(select(maxfdp1, &rset, NULL, NULL, NULL) <0 )
		{	
			if(errno == EINTR)
				continue;
			else
			{
				fprintf(stdout, "Error is : %s\n", strerror(errno));
				err_quit("Error in select function");
			}
		}

		if(FD_ISSET(pfsockfd, &rset))
		{
			recvFromPF();
		}
		if(FD_ISSET(listenfd, &rset))
		{
			if( (connfd = accept(listenfd, (SA *)&cliaddr, &clilen)) < 0)
			{
				if(errno = EINTR)
					continue;
				else
					err_sys("Accept error\n");
			}
			//sleep(7);
			recvFromUnix();
		}
	}
}

void recvFromPF()
{
	int fd;
	struct cacheTable ct;
	char tempipaddr[50], buffer[1000];
	unsigned char tempmacaddr[6];
	struct sockaddr_ll pf;
	void* recvbuf = (void *) malloc (ETH_FRAME_LEN);
	int size = sizeof(pf), n = 1;
	void* data = recvbuf + 14;
	unsigned char src_mac[6];
	unsigned char dest_mac[6];
	struct arpheader *arphdr, ah;
	struct hwaddr *HWaddr;
	arphdr = (struct arpheader *) data;
	HWaddr = (struct hwaddr *) buffer;
	Recvfrom(pfsockfd, recvbuf, ETH_FRAME_LEN, 0, (SA *) &pf, &size);
	//printf("Errno after recvfrom: %d\n", errno);
	//printf("Received some message\n");
	ah = *arphdr;
	printf("************************************************************************************\n");
	if (ah.oper == 1)
		printf("Received ARP Request packet: \n");
	else if (ah.oper == 2)
		printf("Received ARP Reply packet: \n");
	printf("ETH Destination MAC: ");
	printf("%02x:%02x:%02x:%02x:%02x:%02x\n",ah.tha[0], ah.tha[1], ah.tha[2], ah.tha[3], ah.tha[4], ah.tha[5]);
	printf("ETH Sourec MAC: ");
	printf("%02x:%02x:%02x:%02x:%02x:%02x\n",ah.sha[0], ah.sha[1], ah.sha[2], ah.sha[3], ah.sha[4], ah.sha[5]);
	printf("ETH type: 0x%04x\n", ARP_PROTO);
	printf("Source IP address: %s\n", ah.spa);
	printf("Destination IP address: %s\n", ah.tpa);
	printf("ID_Field: 0x%04x\n", ID_FIELD);
	printf("************************************************************************************\n\n");
	if(!(strcmp(arphdr->tpa, cache_table[0].ipaddr)))
	{
		
		if(arphdr->oper == 1)
		{
			//printf("I am the destination\n");
			ah.oper = 2;
			strcpy(tempipaddr, ah.spa);
			strcpy(ah.spa, ah.tpa);
			strcpy(ah.tpa, tempipaddr);
			memcpy(ah.tha, ah.sha, IF_HADDR);
			memcpy(ah.sha, cache_table[0].ha, IF_HADDR);

			ct.htype = ah.htype;
			ct.sll_ifindex = 2;
			ct.connfd = -1;
			strcpy(ct.ipaddr, ah.tpa);
			memcpy(ct.ha, ah.tha, IF_HADDR);
			addToCache(cache_table, ct, &cacheCount);
			sendFromPF(ah);
		}
		else if(arphdr->oper == 2)
		{
			//printf("Required Mac address for %s is ", ah.spa);
			//printf("%02x:%02x:%02x:%02x:%02x:%02x\n",ah.sha[0], ah.sha[1], ah.sha[2], ah.sha[3], ah.sha[4], ah.sha[5]);
			fd = updateCacheTable(ah.spa, ah.sha);
			if(fd != -1)
			{
				HWaddr->sll_ifindex = 2;
				strcpy(HWaddr->ipaddr, ah.spa);
				HWaddr->sll_halen = 6;
				HWaddr->sll_hatype = 1;
				memcpy(HWaddr->sll_addr, ah.sha, IF_HADDR);
				//printf("Before write to tour after obtaining from arp.\n");
				if ((write(fd, buffer, sizeof(buffer)) < 0))	 //&& (errno == EPIPE))
				{
					printf("Tour process unavailable\n Continue to run arp..\n");
				}
				//printf("After sending reply to tour (after receiiving from PF_PACKET)\n");
				//printf("Errno: %d\n", errno);
				Close(fd);
			}
		}
		
	}
	//else check cache table and update the entry
}

void recvFromUnix()
{
	struct hwaddr *HWaddr;
	struct cacheTable ct;
	struct arpheader ah;
	char buffer[1000];
	int pos;

	HWaddr = (struct hwaddr*) buffer;
	//printf("Unix socket is readable now. Socket descriptor is %d\n", connfd);
	Read(connfd, buffer, sizeof(buffer));
	//printf("Errno: %d\n", errno);
	printf("Received request from tour to find MAC address for node: %s\n",  GetHostname(HWaddr->ipaddr));

	pos = checkCacheTable(HWaddr->ipaddr);
	if(pos >=0)
	{
		printf("MAC address present in the cache table. Replying to tour process..\n\n");
		memcpy(HWaddr->sll_addr, cache_table[pos].ha, IF_HADDR);
		//printf("Before write to tour from cache.\n");
		if ((write(connfd, buffer, sizeof(buffer)) < 0) && (errno == EPIPE))
		{
			printf("Tour process unavailable\n Continue to run arp..\n");
		}
		//printf("After write from cache in recvFromUnix\n");
		//printf("Errno: %d\n", errno);
		Close(connfd);
		return;
	}
	
	ct.htype = HWaddr->sll_hatype;
	ct.sll_ifindex = HWaddr->sll_ifindex;
	ct.connfd = connfd;
	strcpy(ct.ipaddr, HWaddr->ipaddr);
	addToCache(cache_table, ct, &cacheCount);

	ah.htype = 1;
	ah.ptype = 0x0800;
	ah.hlen = 6;
	ah.plen = 4;
	ah.oper = 1;
	memcpy(ah.sha, cache_table[0].ha, IF_HADDR);
	strcpy(ah.spa, cache_table[0].ipaddr);
	unsigned char dest_mac[ETH_ALEN] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
	memcpy(ah.tha, dest_mac, IF_HADDR);
	strcpy(ah.tpa, HWaddr->ipaddr);

	sendFromPF(ah);
}

void sendFromPF(struct arpheader ah)
{
	int send_result;
	void* buffer = (void *)malloc(ETH_FRAME_LEN);
	unsigned char* etherhead = buffer;
	unsigned char* data = buffer + 14;

	struct sockaddr_ll socket_address;
	struct ethhdr *eh = (struct ethhdr *)etherhead;
	struct arpheader *arphdr;
	arphdr = (struct arpheader*) data;

	*arphdr = ah;

	socket_address.sll_family = PF_PACKET;	
	socket_address.sll_protocol = htons(ARP_PROTO);
	socket_address.sll_ifindex  = 2;
	socket_address.sll_halen    = ETH_ALEN;

	// NULL address for sockaddress_ll structure
	socket_address.sll_addr[0]  = 0x00;		
	socket_address.sll_addr[1]  = 0x00;		
	socket_address.sll_addr[2]  = 0x00;
	socket_address.sll_addr[3]  = 0x00;
	socket_address.sll_addr[4]  = 0x00;
	socket_address.sll_addr[5]  = 0x00;
	/*MAC - end*/
	socket_address.sll_addr[6]  = 0x00;		/*not used*/
	socket_address.sll_addr[7]  = 0x00;		/*not used*/

	memcpy((void*)buffer, (void*)ah.tha, ETH_ALEN);
	memcpy((void*)(buffer+ETH_ALEN), (void*)ah.sha, ETH_ALEN);
	eh->h_proto = htons(ARP_PROTO);
	printf("************************************************************************************\n");
	if (ah.oper == 1)
		printf("Sending ARP Request packet: \n");
	else if (ah.oper == 2)
		printf("Sending ARP Reply packet: \n");
	printf("ETH Destination MAC: ");
	printf("%02x:%02x:%02x:%02x:%02x:%02x\n",ah.tha[0], ah.tha[1], ah.tha[2], ah.tha[3], ah.tha[4], ah.tha[5]);
	printf("ETH Sourec MAC: ");
	printf("%02x:%02x:%02x:%02x:%02x:%02x\n",ah.sha[0], ah.sha[1], ah.sha[2], ah.sha[3], ah.sha[4], ah.sha[5]);
	printf("ETH type: 0x%04x\n", ARP_PROTO);
	printf("Source IP address: %s\n", ah.spa);
	printf("Destination IP address: %s\n", ah.tpa);
	printf("ID_Field: 0x%04x\n", ID_FIELD);
	printf("************************************************************************************\n\n");

	send_result = sendto(pfsockfd, (void *) buffer, ETH_FRAME_LEN, 0,
		      (SA *)&socket_address, sizeof(socket_address));
	//printf("After writing to PF_PACKET\n");
	if (send_result < 0) 
	{ 
		printf("Failed to send message.\nSendto failed: Error: %s\n", strerror(errno));
	}

}

void getLocalInterface()
{
	struct hwa_info	*hwa;
	struct sockaddr	*sa;
	struct cacheTable ct;
	//printf("\n");
	for (hwa = Get_hw_addrs(); hwa != NULL; hwa = hwa->hwa_next)
	{
		if(!strcmp(hwa->if_name, "eth0")) //storing my eth0 MAC in a char array
		{
			sa = hwa->ip_addr;
			strcpy(ct.ipaddr,Sock_ntop_host(sa, sizeof(*sa)));
			printf("Local ip address : %s\n", ct.ipaddr);
			printf("Local MAC address: ");
			//printf("Interface index is %d\n", hwa->if_index);
			memcpy(ct.ha, hwa->if_haddr, IF_HADDR);
			printf("%02x:%02x:%02x:%02x:%02x:%02x\n",ct.ha[0], ct.ha[1], ct.ha[2], ct.ha[3], ct.ha[4], ct.ha[5]);
			ct.sll_ifindex = 2;
			ct.htype = 1;
			ct.connfd = -1;
			addToCache(cache_table, ct, &cacheCount);
			break;
		}
	}
	free_hwa_info(hwa);
}

void addToCache(struct cacheTable *cache_table, struct cacheTable ct, int *cacheCount)
{
	//printf("ODR_TABLE: Adding port\n");
   if ( *cacheCount < MAX_ITEMS )
   {
      cache_table[*cacheCount] = ct;
      *cacheCount += 1;
   }
   //print_cacheTable();
}

int updateCacheTable(char ipaddr[], unsigned char macaddr[])
{
	int i, fd = -1;
	for(i=0; i<cacheCount; i++)
	{
		if(!(strcmp(ipaddr, cache_table[i].ipaddr)))
		{
			memcpy(cache_table[i].ha, macaddr, IF_HADDR);
			fd = cache_table[i].connfd;
			cache_table[i].connfd = -1;
			break;
		}
	}
	return fd;
}

int checkCacheTable(char ipaddr[])
{
	int i;
	for(i=0; i<cacheCount; i++)
	{
		if(!(strcmp(ipaddr, cache_table[i].ipaddr)))
			return i;
	}
	return -1;
}

void print_cacheTable()
{
	int i;
	for(i=0; i<cacheCount; i++)
	{
		printf("\nEntry %d\n", i+1);
		printf("Ip address is %s\n", cache_table[i].ipaddr);
		printf("Hw address is %02x:%02x:%02x:%02x:%02x:%02x\n",cache_table[i].ha[0], cache_table[i].ha[1], cache_table[i].ha[2], cache_table[i].ha[3], cache_table[i].ha[4], cache_table[i].ha[5]);
		printf("Hw type is %d\n", cache_table[i].htype);
		printf("Index is %d\n", cache_table[i].sll_ifindex);
		printf("Connfd is %d\n", cache_table[i].connfd);
	}
}

char* GetHostname(char ip[])
{
	struct hostent *hptr;
	struct in_addr Ipaddr;
	inet_pton(AF_INET, ip, &Ipaddr);
	hptr = malloc (sizeof (struct hostent));
	hptr = gethostbyaddr(&Ipaddr, sizeof(Ipaddr), AF_INET);
	strcpy(vm_name,hptr->h_name);
	return vm_name;
}
