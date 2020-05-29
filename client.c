#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <linux/udp.h>
#include <linux/ip.h>
#include <linux/if_packet.h>
#include <netinet/if_ether.h>
#include <net/ethernet.h>
#include <net/if.h>

unsigned short checksum(unsigned short* ip)
{
    int csum = 0;
    int ptr_sum;
    unsigned short* ptr = ip;

    for (int i = 0; i < 10; i++, *ptr++)
    {
        csum += *ptr;
    }
    ptr_sum = csum >> 16;
    csum += ptr_sum;
    return ~csum;
}

int main()
{
    int sock;
    int size;
    int bytes_read;
    char buff[1024];
    char buff2[1024];
    char message[1024];
    char source[INET_ADDRSTRLEN];
    struct sockaddr_ll server;
    struct sockaddr_ll client;
    struct iphdr* ip;
    struct udphdr* udp;
    struct ether_header* eth;
    struct iphdr* ip_header;
    struct udphdr* udp_header;
    struct ether_header* eth_header;

    unsigned char mac_client[6] = {0x74, 0x04, 0x2B, 0x83, 0x93, 0x86};
    unsigned char mac_server[6] = {0x30, 0x10, 0xB3, 0xC4, 0x19, 0xFD};

    sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sock == -1)
    {
        fprintf(stderr, "Incorrect client socket\n");
        exit(1);
    }

    server.sll_family = AF_PACKET;
    server.sll_ifindex = if_nametoindex("wifi0");
    server.sll_halen = ETH_ALEN;
    memmove((void*)(server.sll_addr), (void*)mac_server, ETH_ALEN);

    eth = (struct ether_header*)buff2;
    ip = (struct iphdr*) (buff2 + sizeof(struct ether_header));
    udp = (struct udphdr*) (buff2 + sizeof(struct ether_header) + sizeof(struct iphdr));

    for (int i = 0; i < 6; i++)
    {
        eth->ether_shost[i] = mac_client[i];
        eth->ether_dhost[i] = mac_server[i];
    }
    eth->ether_type = htons(ETHERTYPE_IP);

    ip->version = 4;
    ip->ihl = 5;
    ip->tos = 0;
    ip->tot_len = htons((ip->ihl * 4) + sizeof(struct udphdr) + strlen(message) + 1);
    ip->id = htons(11111);
    ip->ttl = 64; 
    ip->frag_off = 0;
    ip->protocol = IPPROTO_UDP;
    ip->check = checksum((unsigned short*)ip);
    ip->saddr = inet_addr("192.168.1.107");
    ip->daddr = inet_addr("192.168.1.100");

    udp->source = htons(0xBBAA);
    udp->dest = htons(0xAABB);
    udp->len = htons(sizeof(struct udphdr) + sizeof(message));
    udp->check = 0;

    while(1)
    {
        fgets(message, 1024, stdin);
        memcpy(buff2 + sizeof(*eth) + sizeof(*ip) + sizeof(*udp), message, sizeof(message));

        size = sizeof(server);
        bytes_read = sendto(sock, buff2, (sizeof(*eth) + sizeof(*ip) + sizeof(*udp) + sizeof(message)), 0, (struct sockaddr*) &server, size);
        if (bytes_read == -1)
        {
            fprintf(stderr, "Incorrect client send\n");
            perror("sendto()");
            exit(1);
        }

        printf("Ingoing: %s", buff2 + sizeof(*eth) + sizeof(*ip) + sizeof(*udp));
        bytes_read = recvfrom(sock, buff, 1024, 0, NULL, NULL);
        if (bytes_read == -1)
        {
            fprintf(stderr, "Incorrect client recvfrom\n");
            exit(1);
        }

        eth_header = (struct ether_header*)buff;
        ip_header = (struct iphdr*)(buff + sizeof(struct ether_header));
        udp_header = (struct udphdr*)(buff + sizeof(struct ether_header) + sizeof(struct iphdr));

        inet_ntop(AF_INET, &ip_header->saddr, source, INET_ADDRSTRLEN);

        if ((strcmp(source, "192.168.1.100") == 0) && (ntohs(udp_header->dest) == 0xBBAA))
        {
            printf("Outgoing: %s", (char*)(buff + sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct udphdr)));
        }
        memset(buff, 0, 1024);
    }

    shutdown(sock, SHUT_RDWR);
    return 0;
}