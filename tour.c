#include "unp.h"
#include <netdb.h>
#include "hw_addrs.h"
//#include <linux/ip.h>

#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <sys/socket.h>
#include <net/ethernet.h> 
#include <netinet/ip.h> 
#include <sys/types.h>        // needed for socket(), uint8_t, uint16_t, uint32_t
#include <sys/socket.h>       // needed for socket()
#include <linux/if_ether.h>   // ETH_P_IP = 0x0800, ETH_P_IPV6 = 0x86DD
#include <linux/if_packet.h>  // struct sockaddr_ll (see man 7 packet)
#include <errno.h>            // errno, perror()
#include <sys/time.h>

#define ID_FIELD 6849
#define ARP_PATH "/tmp/arp8132"
#define BUFSIZE 1500
#define ETH_HDRLEN 14  // Ethernet header length
#define IP4_HDRLEN 20  // IPv4 header length
#define ICMP_HDRLEN 8  // ICMP header length for echo request, excludes data
#define IF_HADDR 6


struct tour_packet
{
    char nodes[20][50];
    char mc_addr[50];
    char mc_port[10];
    int position;
    int total;
};

struct hwaddr {
    int             sll_ifindex;	 /* Interface number */
	char 			ipaddr[50];
    unsigned short  sll_hatype;	 	 /* Hardware type */
    unsigned char   sll_halen;		 /* Length of address */
    uint8_t		 	sll_addr[IF_HADDR];	 /* Physical layer address */
};

struct ping_table
{
	char ipaddr[50];
	int nsent;
}ping_ip[100];

char* GetHostByName(char vm[]);
char* getlocalhost();
void joinMulticast(char ipaddr[], char port[]);
void listenSockets();
void sendFromRT(struct tour_packet tp);
void recvFromRT();
//void sendEchoRequest(char precedingIP[]);
int areq(struct hwaddr hwa);
char* GetHostname(char ip[]);
void readloop(int pingrecvsockfd);
void tv_sub1(struct timeval *out, struct timeval *in);
void proc_v4 (char *ptr, struct timeval *tvrecv, char recvaddr[], ssize_t len);
void sig_alrm(int signo);
void send_v4 (char ping_ip[], int nsent);
unsigned short in_cksum(unsigned short *addr, int len);
uint16_t icmp4_checksum (struct icmp icmphdr, uint8_t *payload, int payloadlen);
void getlocalpinghost();
char * allocate_strmem (int len);
uint8_t * allocate_ustrmem (int len);
int * allocate_intmem (int len);
void add_ping_ip (char ipaddr[]);
int check_ping_ip(char check_ipaddr[]);
void send_lastnode_multicast();
void getCurrentTime ();

char timebuf[100];
char vm_name[50], localIP[50];
char vmIP[50], sourceIP[50];
int MY_PROTO = 200;
int no_ping_flag = 0;
int rt, unixsockfd, udpsend, udprecv; 	//sockets
int multicastFlag = 0;
int last_node_flag = 0, last_node_ping_count = 0;
int sendFlag = 1;
int alarm_flag = 0;
int last_node_multicast_flag = 0;
char sendbuf[BUFSIZE];
char ipaddr[30];
struct sockaddr_in recvaddr, sendaddr;
char *host;
//int nsent;
int ping_count = 0;
pid_t pid;
//int pingrecvsockfd;
int datalen = 56;
//Need to change global declaration
char ping_src_ip[20], ping_dst_ip[20];
uint8_t ping_src_mac[IF_HADDR];
uint8_t ping_dst_mac[IF_HADDR];
//char precedingIP[50];


struct sockaddr_un servaddr; //arp
struct sockaddr *sasend, *sarecv, *safrom;
socklen_t salen, len;

int main(int argc, char* argv[])
{
	int i, optval = 1, ret = 0;
	struct tour_packet tp;
	char buffer[10];
	pid = getpid() & 0xffff;
	rt = Socket(AF_INET, SOCK_RAW, MY_PROTO); 	//create route traversal socket
	Signal(SIGALRM, sig_alrm); //sigalarm handling
	if (setsockopt(rt, IPPROTO_IP, IP_HDRINCL, &optval, sizeof(int)) < 0)
        perror ("setsockopt error");
    //ret = system("su");
    /*ret = system("ulimit -n 16384");

    if(ret == -1)
    {
    	printf("Failed to set max open files in system. Ping may terminate abruptly due to 'Too many open files error'\n");
    }
    ret = system("ulimit -n");*/
    strcpy(localIP, getlocalhost());
	if(argc!=1) //I am starting the tour
	{
		printf("Starting the tour from node %s\n", GetHostname(getlocalhost()));
		printf("List of nodes in the tour: \n");
		strcpy(tp.nodes[0],getlocalhost());
		//printf("Ip address of the source node is : %s\n", tp.nodes[0]);
		for(i=1;i<argc;i++)
		{
			
			printf("Node %d : %s\n", i+1, argv[i]);
			strcpy(tp.nodes[i],GetHostByName(argv[i]));
			//printf("The ip address of the node is %s\n", tp.nodes[i]);
		}

		strcpy(tp.mc_addr, "228.0.0.255");
		strcpy(tp.mc_port, "45000");
		printf("Tour's Multicast Ip address: %s, Port#: %s\n", tp.mc_addr, tp.mc_port);
		tp.position = 1;
		tp.total = argc - 1;

		joinMulticast(tp.mc_addr, tp.mc_port);
		
		sendFromRT(tp); //starting tour
	}
	else
		printf("Waiting for tour packet..\n");
	
	listenSockets(); 

	exit(1);
}

void joinMulticast(char ipaddr[], char port[])
{
	int optval = 1;

	udpsend = Udp_client(ipaddr, port, (struct sockaddr **) &sasend, &salen); //why put to (void **)
	udprecv = Socket(sasend->sa_family, SOCK_DGRAM, 0);

	Setsockopt(udprecv, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(int));
	sarecv = Malloc(salen);
	memcpy(sarecv, sasend, salen);
	Bind(udprecv, sarecv, salen);

	Mcast_join(udprecv, sasend, salen, NULL, 0);
	//Mcast_set_loop(udpsend, 0);
	Mcast_set_ttl(udpsend, 1);

	multicastFlag = 1;
	printf("\nJoined multicast group: Ip address: %s, Port#: %s\n", ipaddr, port);	
}


void sendFromRT(struct tour_packet tp)
{
	struct iphdr *ip;
	struct sockaddr_in dest;
	struct tour_packet *tourPacket;
	char *data;
	char packet[1400];

	ip = (struct iphdr*) packet;
    data = packet + sizeof(struct iphdr);

    tourPacket = (struct tour_packet*) data;
    *tourPacket = tp;

    //printf("position is %d\n", tourPacket->position);

    ip->ihl         = 5;
    ip->version     = 4;
    ip->tot_len     = sizeof(struct iphdr);
    ip->protocol    = MY_PROTO;
    ip->saddr       = inet_addr(tp.nodes[tp.position - 1]);
    ip->daddr       = inet_addr(tp.nodes[tp.position]);
    ip->id          = htons(ID_FIELD);
    ip->ttl         = 1;

    dest.sin_family       = AF_INET;
    dest.sin_addr.s_addr  = ip->daddr;
    sendto(rt, packet, 1400, 0, (SA* )&dest, sizeof(struct sockaddr_in));
    printf("Sending tour packet to node %s\n\n", GetHostname(tp.nodes[tp.position]));
}

void listenSockets()
{
	int maxfdp1, i, n, size;
	int ping_flag = 0;
	int selreturn, pingrecvsockfd;
	char recvbuffer[100], sendbuffer[100];
	fd_set rset;
	struct timeval ping_timeout;
	pingrecvsockfd = Socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
	setuid(getuid());
	//strcpy(ping_dst_ip, precedingIP);
	size = 60*1024;
	setsockopt(pingrecvsockfd, SOL_SOCKET, SO_RCVBUF, &size, sizeof(size));
	
	for(;;)
	{
		//printf("In select\n\n\n\n\n\n\n\n");
		FD_ZERO(&rset);
		FD_SET(rt, &rset);
		FD_SET(pingrecvsockfd, &rset);
		//ping timeout
		if(multicastFlag)
		{
			FD_SET(udprecv, &rset);
			//maxfdp1 = 
		}

		ping_timeout.tv_sec = 1;
		ping_timeout.tv_usec = 0;

		//maxfdp1 = rt + 1;
		//printf("maxfdp1: %d\n",maxfdp1);
		//printf("FD_SETSIZE is %d\n", FD_SETSIZE);
		//printf("before select\n");
		selreturn = select(FD_SETSIZE, &rset, NULL, NULL, &ping_timeout);
		if(selreturn < 0 )
		{	
			if(errno == EINTR)
				continue;
			else
			{
				fprintf(stdout, "Error: %s\n", strerror(errno));
				err_quit("Error in select function");
			}
		}

		if(FD_ISSET(rt, &rset)) //tour socket
		{
			recvFromRT();
			ping_flag = 1;
		}
		if(FD_ISSET(udprecv, &rset)) //multicast socket
		{
			n = Recvfrom(udprecv, recvbuffer, sizeof(recvbuffer), 0, sarecv, &len);
			recvbuffer[n] = 0;
			printf("Node %s: Received: %s\n", GetHostname(getlocalhost()), recvbuffer);
			
			if(sendFlag)
			{
				ping_flag = 0;
				strcpy(sendbuffer, "<<<<<Node ");
				strcat(sendbuffer, GetHostname(getlocalhost()));
				strcat(sendbuffer, ". I am a member of the group>>>>>");
				printf("Node %s: Sending: %s\n", GetHostname(getlocalhost()), sendbuffer);
				Sendto(udpsend, sendbuffer, sizeof(sendbuffer), 0, (SA *) sasend, salen);
				sendFlag = 0;
				//printf("\nSetting alarm in udprecv socket select\n");
				alarm(5);
			}
		}

		if (FD_ISSET(pingrecvsockfd, &rset))
		{
			//printf("In pingrecvsockfd\n");
			if((ping_flag == 1) && !(no_ping_flag))
			{
				readloop(pingrecvsockfd);
			}
			if((last_node_flag == 1) && !(no_ping_flag))
			{
				last_node_ping_count++;
				//printf("last_node_ping_count: %d\n",last_node_ping_count);
			}
			if(last_node_ping_count == 5)
			{
				send_lastnode_multicast();
				ping_flag = 0;
				last_node_multicast_flag = 1;
				//printf("Setting alarm in pingrecvdsockfd for last_node_flag\n");
				alarm(5);
			}
		}
		if(selreturn == 0)
		{
			//printf("In select timeout\n");
			if (ping_flag == 1)
			{
				//printf("Timeout for ping sending\n");
				for (i=0; i<ping_count; i++)
				{
					//printf("Ping ipaddr in select before send_v4: %s\n", ping_ip[i].ipaddr);
					if ((!no_ping_flag) && (strcmp(ping_ip[i].ipaddr,localIP)))
					{
						send_v4(ping_ip[i].ipaddr, ping_ip[i].nsent);
						ping_ip[i].nsent++;
					}
				}
			}
		}
		if (alarm_flag == 1)
		{
			printf("\n***********Exiting the Tour application, Goodbye..!!***********\n\n");
			Close(rt);
			Close(pingrecvsockfd);
			Close(udprecv);
			exit(0);
		}
	}
}

void recvFromRT()
{
	struct iphdr *ip_reply;
	char buffer[1400];
	struct tour_packet *tp, tourPacket;
	struct sockaddr_in sin;
	int size, sent_counter = 0, i, curr = 0;
	size = sizeof(sin);
	ip_reply = (struct iphdr*) buffer;

	void* data = buffer + sizeof(struct iphdr);
	tp = (struct tour_packet *) data;

	Recvfrom(rt, buffer, 1400, 0, (struct sockaddr *)&sin, &size);
	printf("\nReceived Tour packet from node %s\n", GetHostname(tp->nodes[tp->position-1]));

	if(!(multicastFlag))
		joinMulticast(tp->mc_addr, tp->mc_port);

	if(tp->position != tp->total)
	{
		tp->position++;
		tourPacket = *tp;
		//printf("in recvfromRT, sending tourpacket to %s\n");
		sendFromRT(tourPacket);
		//if((tp->poition -1) == 1)
		//	curr = tp->position - 1;
		//else
		curr = tp->position - 2;
		//printf("value of curr if not last node: %d\n", curr);
	}
	else
	{
		last_node_flag = 1;
		curr = tp->position - 1;
	}

	if (!(check_ping_ip(tp->nodes[curr])))
	{
		add_ping_ip(tp->nodes[curr]);
		if ((!no_ping_flag) && (strcmp(tp->nodes[curr],localIP)))
		{
			for (i=0; i<ping_count; i++)
			{
				if(!(strcmp(tp->nodes[curr], ping_ip[i].ipaddr)))
				{
					sent_counter = ping_ip[i].nsent;
					ping_ip[i].nsent++;
				}
			}
			//printf("Ping ipaddr before send_v4: %s\n", tp->nodes[curr]);
			send_v4(tp->nodes[curr], sent_counter);
		}
	}
	else
	{
		printf("Already initiated ping previously to the node: %s. So ignoring new ping initiation to the same node.\n", GetHostname(tp->nodes[curr]));
	}
}

void send_lastnode_multicast()
{
	char sendbuffer[100];
	//readloop(precedingIP); //change
	strcpy(sendbuffer, "<<<<<This is node ");
	strcat(sendbuffer, GetHostname(getlocalhost()));
	strcat(sendbuffer,". Tour has ended. Group members please identify yourselves>>>>>");
	printf("\nNode %s: Sending: %s\n", GetHostname(getlocalhost()), sendbuffer);
	//sleep (5); //remove
	Sendto(udpsend, sendbuffer, sizeof(sendbuffer), 0, (SA *) sasend, salen);
	//printf("After sending send_lastnode_multicast, setting alarm(5)\n");
	//alarm(5);
}

int check_ping_ip(char check_ipaddr[])
{
	int i;
	//printf("In check_ping_ip for %s\n", check_ipaddr);
	for (i=0; i < ping_count; i++)
	{
		if (!strcmp(ping_ip[i].ipaddr, check_ipaddr))
		{
			return 1;
		}
	}
	return 0;
}

void add_ping_ip (char ipaddr[])
{
	int i;
	//printf("In add_ping_ip for %s\n", ipaddr);
	strcpy(ping_ip[ping_count].ipaddr, ipaddr);
	ping_ip[ping_count].nsent = 0;
	ping_count++;
}

/* ping handling*/
void readloop(int pingrecvsockfd)
{
	int addrlen;
	ssize_t n;
	struct hostent *he;
	char recvbuf[BUFSIZE];
	char *recvipaddr;
	struct timeval tval;
	//sig_alrm(SIGALRM); // change the call
	addrlen = sizeof(recvaddr);
	n = recvfrom(pingrecvsockfd, recvbuf, sizeof(recvbuf), 0, (SA *) &recvaddr, &addrlen);
	if (n < 0)
	{
		perror ("recvfrom error");
	}
	//printf("In readloop after recvfrom\n");
	recvipaddr = Sock_ntop_host((SA *)&recvaddr, sizeof(recvaddr));
	//he = gethostbyaddr(&recvaddr, sizeof (recvaddr), AF_INET);
	//printf("Host name: %s\n", he->h_name);
	//printf("Message received from %s\n", recvipaddr);
	Gettimeofday(&tval, NULL);
	//printf("Received %u bytes\n", n);
	proc_v4(recvbuf, &tval, recvipaddr, n);
}


void tv_sub1(struct timeval *out, struct timeval *in)
{
	if ((out->tv_usec -= in->tv_usec) < 0)
	{
		--out->tv_sec;
		out->tv_usec += 1000000;
	}
	out->tv_sec -= in->tv_sec;
}

void proc_v4 (char *ptr, struct timeval *tvrecv, char recvaddr[], ssize_t len)
{
	int hlen, icmplen;
	double rtt;
	struct ip *ip;
	struct icmp *icmp;
	struct timeval *tvsend;

	ip = (struct ip*) ptr;
	hlen = ip->ip_hl << 2;
	//printf("in proc_v4\n");
	//printf ("IP header length: %d\n", hlen);
	if(ip->ip_p != IPPROTO_ICMP)
	{
		printf("Received packet not of ICMP. Ignoring.\n");
		return;
	}

	icmp = (struct icmp *) (ptr +hlen);
	icmplen = len - hlen;
	//printf("ICMP length: %d\n", icmplen);
	if( icmplen < 8)
	{
		printf("ICMP header length less than 8 bytes. Malformed packet. Ignoring\n");
		return;	
	}	
	if (icmp->icmp_type == ICMP_ECHOREPLY)
	{
		//printf("ICMP_ID: %d\n", icmp->icmp_id);
		if(icmp->icmp_id != htons(pid))
		{
			printf("Received ICMP packet ID %d value incorrect. Ignoring the packet.\n",htons(icmp->icmp_id));
			return;
		}
		if(icmplen < 16)
		{
			printf("Received packet, ICMP total lenth less than 16 bytes\n");
			return;
		}
		tvsend = (struct timeval *) icmp->icmp_data;
		tv_sub1(tvrecv, tvsend);
		rtt = tvrecv->tv_sec *1000.0 + tvrecv->tv_usec/1000.0;
		printf("%d bytes from %s: seq = %u, ttl = %d, rtt = %0.3f ms\n", icmplen,recvaddr, icmp->icmp_seq, ip->ip_ttl, rtt);
	}
	else
	{
		//printf("REceived reply not ECHOREPLY, ignoring.\n type: %d\n", icmp->icmp_type);
	}
}

void sig_alrm(int signo)
{
	//printf("In sig_alrm: setting alarm_flag to 1\n");
	alarm_flag = 1;
	return;
}

void send_v4 (char ping_ip[], int nsent)
{
	int len, i, *ip_flags, frame_length, status;
	int sendsockfd, bytes, arp_ret;
	struct icmp icmp;
	//char strip[20];
	char *interface, *target;
	uint8_t *data, *ether_frame;
	struct ip iphdr;
	//struct icmp icmphdr;
	struct sockaddr_in *ipv4;
  	struct sockaddr_ll device;

  	struct hwaddr hwa;
	hwa.sll_ifindex = 2;
	hwa.sll_hatype = 1;
	hwa.sll_halen = 6;
	//printf("Destination ip is %s\n", precedingIP);
	strcpy(ping_dst_ip, ping_ip);
	strcpy(hwa.ipaddr, ping_ip);

	arp_ret = areq(hwa);
	if (arp_ret == 1)
	{
		printf("Fetching MAC address from ARP failed due to timeout\n");
		printf("Ping attempt initiation failed, discarding ping process to %s\n", GetHostname(ping_dst_ip));
		no_ping_flag = 1;
		return;
	}

	//uint8_t *data, *src_mac, *dst_mac, *ether_frame;
	sendsockfd = Socket(PF_PACKET, SOCK_RAW, htons (ETH_P_ALL)); // for sending on PF_PACKET socket
	//ping_src_mac = allocate_ustrmem (6);
	//ping_dst_mac = allocate_ustrmem (6);
	//data = allocate_ustrmem (IP_MAXPACKET); //65535
	ether_frame = allocate_ustrmem (IP_MAXPACKET);
	interface = allocate_strmem (40);
	target = allocate_strmem (40);
	//ping_src_ip = allocate_strmem (INET_ADDRSTRLEN);
	//ping_dst_ip = allocate_strmem (INET_ADDRSTRLEN);
	data = allocate_ustrmem (IP_MAXPACKET);
	ip_flags = allocate_intmem (4);
	//struct ethhdr *eh = (struct ethhdr *)ether_frame;
	// Interface to send packet through.
  	strcpy (interface, "eth0");
  	getlocalpinghost(); // to set src_ip and src_mac
  	//printf ("MAC address for interface %s is ", interface);
  	for (i=0; i<5; i++) {
    	//printf ("%02x:", ping_src_mac[i]);
 	 }
  	//printf ("%02x\n", ping_src_mac[5]);
  	memset (&device, 0, sizeof (device));
	/*if ((device.sll_ifindex = if_nametoindex (interface)) == 0) {
		perror ("if_nametoindex() failed to obtain interface index ");
		exit (EXIT_FAILURE);
	}*/
	device.sll_ifindex = 2;
  	//printf ("Index for interface %s is %i\n", interface, device.sll_ifindex);

	// Set destination MAC address: you need to fill these out - change value 00:0c:29:49:3f:5b
	
	
	device.sll_family = AF_PACKET;
	memcpy (device.sll_addr, ping_src_mac, 6);
	device.sll_halen = htons (6);

	iphdr.ip_hl = IP4_HDRLEN / sizeof (uint32_t);
	//printf("iphdr.ip_hl: %d\n",iphdr.ip_hl);
	// Internet Protocol version (4 bits): IPv4
	iphdr.ip_v = 4;

	// Type of service (8 bits)
	iphdr.ip_tos = 0;

	// Total length of datagram (16 bits): IP header + ICMP header + ICMP data
	iphdr.ip_len = htons (IP4_HDRLEN + ICMP_HDRLEN + datalen);

	// ID sequence number (16 bits): unused, since single datagram
	iphdr.ip_id = htons (0);

	// Flags, and Fragmentation offset (3, 13 bits): 0 since single datagram

	// Zero (1 bit)
	ip_flags[0] = 0;

	// Do not fragment flag (1 bit)
	ip_flags[1] = 0;

	// More fragments following flag (1 bit)
	ip_flags[2] = 0;

	// Fragmentation offset (13 bits)
	ip_flags[3] = 0;
	iphdr.ip_off = htons ((ip_flags[0] << 15)
                      	+ (ip_flags[1] << 14)
						+ (ip_flags[2] << 13)
						+  ip_flags[3]);

	// Time-to-Live (8 bits): default to maximum value
	iphdr.ip_ttl = 255;

	// Transport layer protocol (8 bits): 1 for ICMP
	iphdr.ip_p = IPPROTO_ICMP;
	//printf("Before inet_pton\n");
	// Source IPv4 address (32 bits)
	if ((status = inet_pton (AF_INET, ping_src_ip, &(iphdr.ip_src))) != 1) {
	fprintf (stderr, "inet_pton() failed.Error message: %s\n", strerror (status));
	exit (EXIT_FAILURE);
	}

	// Destination IPv4 address (32 bits)
	if ((status = inet_pton (AF_INET, ping_dst_ip, &(iphdr.ip_dst))) != 1) {
	fprintf (stderr, "inet_pton() failed.Error message: %s\n", strerror (status));
	exit (EXIT_FAILURE);
	}
	//printf("After inet_pton\n");
	// IPv4 header checksum (16 bits): set to 0 when calculating checksum
	iphdr.ip_sum = 0;
	iphdr.ip_sum = in_cksum((uint16_t *) &iphdr, IP4_HDRLEN);
	//printf("After ip checksum\n");

	//icmp = (struct icmp *) sendbuf;
	icmp.icmp_cksum = 0;
	icmp.icmp_type = ICMP_ECHO;
	icmp.icmp_code = 0;
	icmp.icmp_id = htons(pid);
	icmp.icmp_seq = nsent;
	//icmp.icmp_data = 0;
	memset(data, 0xb2, datalen);
	//printf("After icmp data memset\n");
	//Gettimeofday((struct timeval *) icmp.icmp_data, NULL);
	Gettimeofday((struct timeval *) data, NULL);
	len = 8 + datalen;
	
	//icmp.icmp_cksum = in_cksum((u_short *) &icmp , len);
	
	icmp.icmp_cksum = icmp4_checksum (icmp, data, datalen);
	//printf("ICMP checksum: %u\n", icmp.icmp_cksum);
	//sendaddr.sin_family = AF_INET;
	//inet_pton(AF_INET, ipaddr, &sendaddr.sin_addr.s_addr);
	//inet_ntop(AF_INET, &(sendaddr.sin_addr.s_addr), strip, sizeof(strip));
	// Destination and Source MAC addresses
  	memcpy (ether_frame, ping_dst_mac, 6);
  	memcpy (ether_frame + 6, ping_src_mac, 6);

  	//alternative way
  	ether_frame[12] = ETH_P_IP / 256;
  	ether_frame[13] = ETH_P_IP % 256;
	

	// Next is ethernet frame data (IPv4 header + ICMP header + ICMP data).

	// IPv4 header
	//printf("Filling Ip header at %x\n", ether_frame + ETH_HDRLEN)''
	memcpy (ether_frame + ETH_HDRLEN, &iphdr, IP4_HDRLEN);

	// ICMP header 
	memcpy (ether_frame + ETH_HDRLEN + IP4_HDRLEN, &icmp, len);

	//ICMP data
	memcpy (ether_frame + ETH_HDRLEN + IP4_HDRLEN + ICMP_HDRLEN, data, datalen);

	frame_length = ETH_HDRLEN + IP4_HDRLEN + ICMP_HDRLEN + datalen;
	//printf("frame_length: %d\n", frame_length);
	// Send ethernet frame to socket.
	//printf("before sendto\n");
	getCurrentTime();
	if ((bytes = sendto (sendsockfd, ether_frame, frame_length, 0, (struct sockaddr *) &device, sizeof (device))) <= 0) 
	{
		perror ("sendto() failed");
		exit (1);
	}
	printf("\nPING %s (%s): %d data bytes at time: %s", ping_ip, ping_ip, (bytes-34), timebuf); //subtracting ETH and IP headers to get only payload size
	// Close socket descriptor.
	Close (sendsockfd);
	// Free allocated memory.
	//free (ping_src_mac);
	//free (ping_dst_mac);
	free (data);
	free (ether_frame);
	free (interface);
	free (target);
	//free (ping_src_ip);
	//free (ping_dst_ip);
	free (ip_flags);
	//printf("Sendaddr: %s\n", strip);
	//Sendto(recvsockfd, sendbuf, len, 0, (SA *) &sendaddr, sizeof(sendaddr)); 
}

char* GetHostByName(char vm[])
{
	struct hostent *hptr;
	hptr = malloc (sizeof (struct hostent));
	if((hptr = gethostbyname(vm)) == NULL)
	{
		herror("gethostbyname error: ");
		exit(1);
	}
			
		if(inet_ntop(hptr->h_addrtype, *(hptr->h_addr_list), vmIP, sizeof(vmIP)) == NULL )
			printf("inet_ntop error");
	return vmIP;
	//free(hptr);
}

char* getlocalhost()
{
	struct hwa_info	*hwa;
	struct sockaddr	*sa;
	//printf("\n");
	for (hwa = Get_hw_addrs(); hwa != NULL; hwa = hwa->hwa_next)
	{
		if(!strcmp(hwa->if_name, "eth0"))
		{
			sa = hwa->ip_addr;
			strcpy(sourceIP,Sock_ntop_host(sa, sizeof(*sa)));
			break;
		}
	}
	free_hwa_info(hwa);
	return sourceIP;
}

unsigned short in_cksum(unsigned short *addr, int len)
{
    register int sum = 0;
    u_short answer = 0;
    register u_short *w = addr;
    register int nleft = len;
    /*
     * Our algorithm is simple, using a 32 bit accumulator (sum), we add
     * sequential 16 bit words to it, and at the end, fold back all the
     * carry bits from the top 16 bits into the lower 16 bits.
     */
    while (nleft > 1)
    {
      sum += *w++;
      nleft -= 2;
    }
    /* mop up an odd byte, if necessary */
    if (nleft == 1)
    {
      *(u_char *) (&answer) = *(u_char *) w;
      sum += answer;
    }
    /* add back carry outs from top 16 bits to low 16 bits */
    sum = (sum >> 16) + (sum & 0xffff);     /* add hi 16 to low 16 */
    sum += (sum >> 16);             /* add carry */
    answer = ~sum;              /* truncate to 16 bits */
    return (answer);
}


// Allocate memory for an array of chars.
char * allocate_strmem (int len)
{
  void *tmp;

  if (len <= 0) {
    fprintf (stderr, "ERROR: Cannot allocate memory because len = %i in allocate_strmem().\n", len);
    exit (EXIT_FAILURE);
  }

  tmp = (char *) malloc (len * sizeof (char));
  if (tmp != NULL) {
    memset (tmp, 0, len * sizeof (char));
    return (tmp);
  } else {
    fprintf (stderr, "ERROR: Cannot allocate memory for array allocate_strmem().\n");
    exit (EXIT_FAILURE);
  }
}

// Allocate memory for an array of unsigned chars.
uint8_t * allocate_ustrmem (int len)
{
  void *tmp;

  if (len <= 0) {
    fprintf (stderr, "ERROR: Cannot allocate memory because len = %i in allocate_ustrmem().\n", len);
    exit (EXIT_FAILURE);
  }

  tmp = (uint8_t *) malloc (len * sizeof (uint8_t));
  if (tmp != NULL) {
    memset (tmp, 0, len * sizeof (uint8_t));
    return (tmp);
  } else {
    fprintf (stderr, "ERROR: Cannot allocate memory for array allocate_ustrmem().\n");
    exit (EXIT_FAILURE);
  }
}

// Allocate memory for an array of ints.
int * allocate_intmem (int len)
{
  void *tmp;

  if (len <= 0) {
    fprintf (stderr, "ERROR: Cannot allocate memory because len = %i in allocate_intmem().\n", len);
    exit (EXIT_FAILURE);
  }

  tmp = (int *) malloc (len * sizeof (int));
  if (tmp != NULL) 
  {
    memset (tmp, 0, len * sizeof (int));
    return (tmp);
  } 
  else 
  {
    fprintf (stderr, "ERROR: Cannot allocate memory for array allocate_intmem().\n");
    exit (EXIT_FAILURE);
  }
}


void getlocalpinghost()
{
	struct hwa_info	*hwa;
	struct sockaddr	*sa;
	//printf("\n");
	for (hwa = Get_hw_addrs(); hwa != NULL; hwa = hwa->hwa_next)
	{
		if(!(strcmp(hwa->if_name, "eth0")))
		{
			sa = hwa->ip_addr;
			strcpy(ping_src_ip,Sock_ntop_host(sa, sizeof(*sa)));
			memcpy(ping_src_mac, hwa->if_haddr, IF_HADDR);
			break;
		}
	}
	free_hwa_info(hwa);
	//return sourceIP;
}

uint16_t icmp4_checksum (struct icmp icmphdr, uint8_t *payload, int payloadlen)
{
  char buf[IP_MAXPACKET];
  char *ptr;
  int chksumlen = 0;
  int i;

  ptr = &buf[0];  // ptr points to beginning of buffer buf

  // Copy Message Type to buf (8 bits)
  memcpy (ptr, &icmphdr.icmp_type, sizeof (icmphdr.icmp_type));
  ptr += sizeof (icmphdr.icmp_type);
  chksumlen += sizeof (icmphdr.icmp_type);

  // Copy Message Code to buf (8 bits)
  memcpy (ptr, &icmphdr.icmp_code, sizeof (icmphdr.icmp_code));
  ptr += sizeof (icmphdr.icmp_code);
  chksumlen += sizeof (icmphdr.icmp_code);

  // Copy ICMP checksum to buf (16 bits)
  // Zero, since we don't know it yet
  *ptr = 0; ptr++;
  *ptr = 0; ptr++;
  chksumlen += 2;

  // Copy Identifier to buf (16 bits)
  memcpy (ptr, &icmphdr.icmp_id, sizeof (icmphdr.icmp_id));
  ptr += sizeof (icmphdr.icmp_id);
  chksumlen += sizeof (icmphdr.icmp_id);

  // Copy Sequence Number to buf (16 bits)
  memcpy (ptr, &icmphdr.icmp_seq, sizeof (icmphdr.icmp_seq));
  ptr += sizeof (icmphdr.icmp_seq);
  chksumlen += sizeof (icmphdr.icmp_seq);

  // Copy payload to buf
  memcpy (ptr, payload, payloadlen);
  ptr += payloadlen;
  chksumlen += payloadlen;

  // Pad to the next 16-bit boundary
  for (i=0; i<payloadlen%2; i++, ptr++) {
    *ptr = 0;
    ptr++;
    chksumlen++;
  }

  return in_cksum ((uint16_t *) buf, chksumlen);
}



/*void sendEchoRequest(char precedingIP[])
{
	struct hwaddr hwa;
	hwa.sll_ifindex = 2;
	hwa.sll_hatype = 1;
	hwa.sll_halen = 6;
	printf("Preceding ip is %s\n", precedingIP);
	strcpy(hwa.ipaddr, precedingIP);
	areq(hwa);
}*/

int areq(struct hwaddr hwa)
{
	int i;
	struct hwaddr *sendHWaddr, *recvHWaddr;
	char sendbuffer[1000], recvbuffer[1000];
	struct timeval arp_timeout;
	fd_set set;
	int maxfdp1, selreturn;

	sendHWaddr = (struct hwaddr*) sendbuffer;
	*sendHWaddr = hwa;

	recvHWaddr = (struct hwaddr*) recvbuffer;

	unixsockfd = Socket(AF_LOCAL, SOCK_STREAM, 0);
	bzero(&servaddr, sizeof(servaddr));
	servaddr.sun_family = AF_LOCAL;
	strcpy(servaddr.sun_path, ARP_PATH);
	//printf("In AREQ calling ARP\n");
	arp_timeout.tv_sec = 5;
	arp_timeout.tv_usec = 0;

	if (connect(unixsockfd, (SA *)&servaddr, sizeof(servaddr)) < 0)
	{
		printf("Connect error: Connection to ARP refused. Terminating the program.\n");
		exit(1);
	}
	Write(unixsockfd, sendbuffer, sizeof(sendbuffer));
	
	FD_ZERO(&set);
	FD_SET(unixsockfd, &set);
	maxfdp1 = unixsockfd + 1;
	selreturn = select(maxfdp1, &set, NULL, NULL, &arp_timeout);
	if(FD_ISSET(unixsockfd, &set))
	{
		Read(unixsockfd, recvbuffer, sizeof(recvbuffer));
	}
	if (selreturn == 0)
	{
		Close(unixsockfd);
		return 1;
	}
	//printf("Destination MAC address is ");
	//printf("%02x:%02x:%02x:%02x:%02x:%02x\n",recvHWaddr->sll_addr[0], recvHWaddr->sll_addr[1], recvHWaddr->sll_addr[2], recvHWaddr->sll_addr[3], recvHWaddr->sll_addr[4], recvHWaddr->sll_addr[5]);
	/*ping_dst_mac[0] = recvHWaddr->sll_addr[0];
	ping_dst_mac[1] = recvHWaddr->sll_addr[1];
	ping_dst_mac[2] = recvHWaddr->sll_addr[2];
	ping_dst_mac[3] = recvHWaddr->sll_addr[3];
	ping_dst_mac[4] = recvHWaddr->sll_addr[4];
	ping_dst_mac[5] = recvHWaddr->sll_addr[5];
	*/
	//printf("Destination MAC in areq:");
	memcpy(ping_dst_mac, recvHWaddr->sll_addr, IF_HADDR);
	/*for (i=0; i<5; i++) {
    	printf ("%02x:", ping_dst_mac[i]);
 	 }
  	printf ("%02x\n", ping_dst_mac[5]);
	*/
	Close(unixsockfd);
	return 0;
	//printf("Unix socket to arp closed succefully\n");
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
	//printf("Client VM in GetClientHostname: %s\n", clientVM);
	//free(clienthptr);
}

void getCurrentTime () 
{
	time_t ticks;
	ticks = time(NULL);
    snprintf(timebuf, sizeof(timebuf), "%.24s\r\n", ctime(&ticks));
    //return timebuf;
}

