#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>

#define MAX_BUFFER_SIZE 1024
#define UNAUTHORIZED_CODE "_@302"

void error(const char *msg)
{
    perror(msg);
    exit(0);
}

int main(int argc, char *argv[]) {

    int sockfd, portno, n;
    struct sockaddr_in serv_addr;
    struct hostent *server;
    char server_addr[INET_ADDRSTRLEN];

    char buffer[MAX_BUFFER_SIZE];

    if (argc < 3)
    {
        fprintf(stderr, "usage %s hostname port\n", argv[0]);
        exit(0);
    }

    portno = atoi(argv[2]);
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0)
        error("ERROR opening socket");

    server = gethostbyname(argv[1]);
    if (server == NULL)
    {
        fprintf(stderr, "ERROR, no such host\n");
        exit(0);
    }

    bzero((char *) &serv_addr, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    bcopy((char *)server->h_addr_list[0],
          (char *)&serv_addr.sin_addr.s_addr, // Check it
          server->h_length);
    serv_addr.sin_port = htons(portno);

    printf("Trying to connect...\n");
    // Connect to server
    if (connect(sockfd, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0)
        error("ERROR connecting");
    printf("Connected.\n");

    if (inet_ntop(AF_INET, &serv_addr.sin_addr, server_addr, INET_ADDRSTRLEN) == NULL) {
        fprintf(stderr, "Could not convert byte to address\n");
    }

    // Authorize client
    bzero(buffer, MAX_BUFFER_SIZE);
    printf("Type pin: ");
    fgets(buffer, MAX_BUFFER_SIZE - 1, stdin);

    n = write(sockfd, buffer, strlen(buffer));
    if (n < 0)
        error("ERROR writing to socket");
    bzero(buffer, MAX_BUFFER_SIZE);

    // Read responce from server
    n = read(sockfd, buffer, MAX_BUFFER_SIZE - 1);
    if (n < 0) {
        error("ERROR reading from socket");
    } else if (n == 0) {
        printf("Lost connection with server...\nAborting!\n");
        close(sockfd);
        exit(0);
    }

    // Check if server responded with unauthorized code
    if(strcmp(buffer, UNAUTHORIZED_CODE) == 0) {
        printf("Unauthorized access!\nShutting down connection...\n");
        close(sockfd);
        exit(0);
    } else {
        printf("%s\n",buffer);
    }

    bzero(buffer, MAX_BUFFER_SIZE);
    while(printf("%s_> ",server_addr), fgets(buffer, MAX_BUFFER_SIZE - 1, stdin), strcmp(buffer, "exit\n") != 0) {

        n = write(sockfd, buffer, strlen(buffer));
        if (n < 0)
            error("ERROR writing to socket");
        bzero(buffer, MAX_BUFFER_SIZE);
        n = read(sockfd, buffer, MAX_BUFFER_SIZE - 1);
        if (n < 0) {
            error("ERROR reading from socket");
        } else if (n == 0) {
            printf("Lost connection with server...\nAborting!\n");
            close(sockfd);
            exit(0);
        }

        printf("%s\n", buffer);
        bzero(buffer, MAX_BUFFER_SIZE -1);
    }
    printf("Exiting..\n");
    close(sockfd);
    return 0;
}
