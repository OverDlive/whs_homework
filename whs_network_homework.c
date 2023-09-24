#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <netinet/ip.h> // <- Add this line
#include <netinet/tcp.h> // <- Add this line
#include <arpa/inet.h>

/* Ethernet header */
struct ethheader {
  u_char  ether_dhost[6]; /* destination host address */
  u_char  ether_shost[6]; /* source host address */
  u_short ether_type;     /* protocol type (IP, ARP, RARP, etc) */
};

void got_packet(u_char *args, const struct pcap_pkthdr *header,
                              const u_char *packet)
{
  struct ethheader *eth = (struct ethheader *)packet;

  if (ntohs(eth->ether_type) == 0x0800) { // check if it's an IP packet
    struct ip *ip = (struct ip *)(packet + sizeof(struct ethheader)); 
    int size_ip = ip->ip_hl*4;

    printf("       From: %s\n", inet_ntoa(ip->ip_src));   
    printf("         To: %s\n", inet_ntoa(ip->ip_dst));

    /* Check the protocol and perform operations according to the protocol type*/
    switch(ip->ip_p) {                                 
        case IPPROTO_TCP:
            printf("   Protocol: TCP\n");
            return;
        case IPPROTO_UDP:
            printf("   Protocol: UDP\n");
            return;
        case IPPROTO_ICMP:
            printf("   Protocol: ICMP\n");
            return;
        default:
            printf("   Protocol: others\n");
            return;
    }
    }
}

int main(){
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    char filter_exp[] = "tcp";
    bpf_u_int32 net;

    // Step 1: Open live pcap session on NIC with name enp0s3
    handle = pcap_open_live("ens33", BUFSIZ, 1, 1000, errbuf);

    // Step 2: Compile filter_exp into BPF psuedo-code
    pcap_compile(handle, &fp, filter_exp, 0, net);
    if (pcap_setfilter(handle, &fp) !=0) {
        pcap_perror(handle,"Error:");
        exit(EXIT_FAILURE);
    }

   // Step3 : Capture packets
    pcap_loop(handle,-1,got_packet,NULL);

    pcap_close(handle); 

    return(0);
}