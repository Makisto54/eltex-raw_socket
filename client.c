#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <linux/udp.h>
#include <linux/ip.h>
#include <sys/socket.h>
#include <netinet/in.h>

int main()
{
    int sock;
    int size;
    int bytes_read;
    char buff[1024];
    char buff2[1024];
    char message[1024];
    char source[INET_ADDRSTRLEN];
    struct sockaddr_in server;
    struct udphdr* udp;
    struct udphdr* udp_header;
    struct iphdr* ip_header;
 
    sock = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
    if (sock == -1)
    {
        fprintf(stderr, "Incorrect client socket\n");
        exit(1);
    }

    server.sin_family = AF_INET;
    server.sin_port = htons(0xAABB);
    server.sin_addr.s_addr = inet_addr("127.0.0.1");

    udp = (struct udphdr*) buff2;

    udp->source = htons(0xBBAA);
    udp->dest = server.sin_port;
    udp->len = htons(sizeof(struct udphdr) + sizeof(message));
    udp->check = 0;

    while(1)
    {
        fgets(message, 1024, stdin);
        memcpy(buff2 + sizeof(*udp), message, sizeof(message));

        size = sizeof(server);
        bytes_read = sendto(sock, buff2, (sizeof(struct udphdr) + sizeof(message)), 0, (struct sockaddr*) &server, size);
        if (bytes_read == -1)
        {
            fprintf(stderr, "Incorrect client recvfrom\n");
            exit(1);
        }

        printf("Ingoing: %s", buff2 + sizeof(*udp));
        bytes_read = recvfrom(sock, buff, 1024, 0, NULL, NULL);
        if (bytes_read == -1)
        {
            fprintf(stderr, "Incorrect client recvfrom\n");
            exit(1);
        }

        ip_header = (struct iphdr*)buff;
        udp_header = (struct udphdr*)(buff + sizeof(struct iphdr));

        inet_ntop(AF_INET, &ip_header->saddr, source, INET_ADDRSTRLEN);

        if ((strcmp(source, "127.0.0.1") == 0) && (ntohs(udp_header->dest) == 0xBBAA))
        {
            printf("Outgoing: %s", (char*)(buff + sizeof(struct iphdr) + sizeof(struct udphdr)));
        }
        memset(buff, 0, 1024);
    }

    shutdown(sock, SHUT_RDWR);
    return 0;
}