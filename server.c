#include <stdio.h>
#include <stdlib.h>
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
    char buf[1024];
    char* buff2 = "You sent the message!\n";
    struct sockaddr_in server;
    struct sockaddr_in client;

    sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock == -1)
    {
        fprintf(stderr, "Incorrect server socket\n");
        exit(1);
    }

    server.sin_family = AF_INET;
    server.sin_port = htons(0xAABB);
    server.sin_addr.s_addr = inet_addr("192.168.1.100");

    size = sizeof(struct sockaddr_in);
    if (bind(sock, (struct sockaddr*) &server, size) == -1)
    {
        fprintf(stderr, "Incorrect server bind\n");
        exit(1);
    }

    while (1)
    {
        size = sizeof(client);
        bytes_read = recvfrom(sock, buf, 1024, 0, (struct sockaddr*) &client, &size);
        if (bytes_read == -1)
        {
            fprintf(stderr, "Incorrect server recvfrom\n");
            exit(1);
        }

        printf("Server received %s from %d %d\n", buf, client.sin_port, client.sin_addr.s_addr);

        if (sendto(sock, buff2, bytes_read, 0, (struct sockaddr*) &client, size) == -1)
        {
            fprintf(stderr, "Incorrect server send\n");
            exit(1);
        }
    }

    shutdown(sock, SHUT_RDWR);
    return 0;
}
