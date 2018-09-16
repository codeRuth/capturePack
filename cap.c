#include <stdio.h>
#include <string.h>
#include <pcap.h>
#include<stdlib.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>


#define SIZE_ETHERNET 14
//#define ETHER_ADDR_LEN  6

/* Ethernet header */
    struct ethernet_hdr {
        u_char ether_dhost[ETHER_ADDR_LEN]; /* Destination host address */
        u_char ether_shost[ETHER_ADDR_LEN]; /* Source host address */
       u_short ether_type; /* IP? ARP? RARP? etc */
   };

    /* IP header */
    struct IP_hdr {
        u_char ip_vhl;      /* version << 4 | header length >> 2 */
        u_char ip_tos;      /* type of service */
        u_short ip_len;     /* total length */
        u_short ip_id;      /* identification */
        u_short ip_off;     /* fragment offset field */
        #define IP_RF 0x8000        /* reserved fragment flag */
        #define IP_DF 0x4000        /* dont fragment flag */
        #define IP_MF 0x2000        /* more fragments flag */
        #define IP_OFFMASK 0x1fff   /* mask for fragmenting bits */
        u_char ip_ttl;      /* time to live */
        u_char ip_p;        /* protocol */
        u_short ip_sum;     /* checksum */
        struct in_addr ip_src;
        struct in_addr ip_dst; /* source and dest address */
    };
    #define IP_HL(ip)       (((ip)->ip_vhl) & 0x0f)
    #define IP_V(ip)        (((ip)->ip_vhl) >> 4)
    /* TCP header */
    struct TCP_hdr {
        u_short th_sport;   /* source port */
        u_short th_dport;   /* destination port */
        u_int32_t th_seq;       /* sequence number */
        u_int32_t th_ack;       /* acknowledgement number */

        u_char th_offx2;    /* data offset, rsvd */
    #define TH_OFF(th)  (((th)->th_offx2 & 0xf0) >> 4)
        u_char th_flags;
    #define TH_FIN 0x01
    #define TH_SYN 0x02
    #define TH_RST 0x04
    #define TH_PUSH 0x08
    #define TH_ACK 0x10
    #define TH_URG 0x20
    #define TH_ECE 0x40
    #define TH_CWR 0x80
    #define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
        u_short th_win;     /* window */
        u_short th_sum;     /* checksum */
        u_short th_urp;     /* urgent pointer */
};

struct UDP_hdr {
        u_short uh_sport;               /* source port */
        u_short uh_dport;               /* destination port */
        u_short uh_ulen;                /* datagram length */
        u_short uh_sum;                 /* datagram checksum */
};

void display(FILE *,struct pcap_pkthdr *,const struct IP_hdr *);

int main(int argc,char *argv[])
{
        if(argc!=2)
        {
                printf("not specified arguments");
                exit(22);
        }

     char *filename=argv[1];
//      strcpy(filename,argv[1]);
//      printf("%s",filename);
     //error buffer
     char errbuff[PCAP_ERRBUF_SIZE];

     //open file and create pcap handler
     pcap_t * handler = pcap_open_offline(filename, errbuff);

     //The header that pcap gives us
    struct pcap_pkthdr *header;

    //The actual packet 
    const u_char *packet;

      int packetCount = 0;
      int i;
      char srcadd[20],dstadd[20];
      //write to file 
      FILE *fp = fopen ( "result.txt", "w" ) ;

      //tcp info
    const struct ethernet_hdr *ethernet; /* The ethernet header */
    const struct IP_hdr *ip; /* The IP header */
    const struct TCP_hdr *tcp; /* The TCP header */
    const struct UDP_hdr *udp;

    u_int size_ip;
    u_int size_tcp;
   
    while (pcap_next_ex(handler, &header, &packet) >= 0)
    {   
        // Show the packet number
        printf("\nPacket # %i\n", ++packetCount);
        fprintf(fp,"\nPacket # %i\n", packetCount);

        ethernet = (struct ethernet_hdr*)(packet);
        ip = (struct IP_hdr*)(packet + SIZE_ETHERNET);
        size_ip = IP_HL(ip)*4;
        if (size_ip < 20)
        {
	  printf("   * Invalid IP header length: %u bytes\n", size_ip);
            return;
        }
        printf("Protocol :%d\n",ip->ip_p);
         if (ip->ip_p == IPPROTO_TCP)
        {
                 printf(" TCP\n");
                 fprintf(fp,"TCP\n");
                if(ntohs(tcp->th_dport)==80)
                    { printf("HTTP\n");
                      fprintf(fp,"HTTP\n");
                    }
                else if(ntohs(tcp->th_dport)==53)
                 {printf("DNS\n");
                      fprintf(fp,"DNS\n");
                     }
                tcp = (struct TCP_hdr*)(packet + SIZE_ETHERNET + size_ip);
                strcpy(srcadd,inet_ntoa(ip->ip_src));
                strcpy(dstadd,inet_ntoa(ip->ip_dst));

                display(fp,header,ip);

                printf("src port: %d dest port: %d \n",ntohs( tcp->th_sport), ntohs(tcp->th_dport));
                fprintf(fp,"src port: %d dest port: %d \n",ntohs( tcp->th_sport),ntohs( tcp->th_dport));

                printf("seq number: %u ack number: %u \n", (unsigned int)tcp-> th_seq, (unsigned int)tcp->th_ack);
                fprintf(fp,"seq number: %u ack number: %u \n", (unsigned int)tcp-> th_seq, (unsigned int)tcp->th_ack);

        }

        else if(ip->ip_p==IPPROTO_UDP)
        {

                udp = (struct UDP_hdr*)(packet + SIZE_ETHERNET + size_ip);

                printf(" UDP\n");
                fprintf(fp," UDP\n");
                if(ntohs(udp->uh_dport)==53)
                     {printf("DNS\n");
                      fprintf(fp,"DNS\n");
                     }
 display(fp,header,ip);


                printf("src port: %d dest port: %d \n",ntohs( udp->uh_sport), ntohs(udp->uh_dport));
                fprintf(fp,"src port: %d dest port: %d \n",ntohs( udp->uh_sport),ntohs( udp->uh_dport));



        }

        else
           display(fp,header,ip);
  }
    fclose (fp);
     return(0);
}

void display(FILE *fp,struct pcap_pkthdr *header,const struct IP_hdr *ip) {        
	char srcadd[20],dstadd[20];

    printf("Packet size: %d bytes\n", (int)header->len); //typecasted from bpf_u_int32 datatype to int
    fprintf(fp,"Packet size: %d bytes\n", (int)header->len);

    // Show a warning if the length captured is different
    if (header->len != header->caplen)
    printf("Warning! Capture size different than packet size: %ld bytes\n",(long int)header->len);

    // Show Epoch Time
    printf("Epoch Time: %d:%d seconds\n",(int)header->ts.tv_sec,(int)header->ts.tv_usec); //typecasted from  __suseconds_t datatype to int
    fprintf(fp,"Epoch Time: %d:%d seconds\n",(int)header->ts.tv_sec, (int)header->ts.tv_usec);//typecasted from __time_t datatype to int 

    strcpy(srcadd,inet_ntoa(ip->ip_src));
    strcpy(dstadd,inet_ntoa(ip->ip_dst));
    printf("src address: %s dest address: %s \n", srcadd,dstadd);
    fprintf(fp,"src address: %s dest address: %s \n", srcadd,dstadd);

}
                                                                                                                             




                                                                                                                            

