#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <signal.h>

#define FATAL(x) do {\
    perror(x);\
    exit(EXIT_FAILURE);\
} while (0)
#define BACKLOG 5
#define BUFSIZE 1024

void usage(){
    fprintf(stderr,"Usage: server PORT\n");
    exit(EXIT_FAILURE);
}

int main(int argc, char *argv[]){

    if (argc == 2)
    {
        struct sockaddr_in my_addr;
        my_addr.sin_family = AF_INET;
        my_addr.sin_port = htons(atoi(argv[1]));
        my_addr.sin_addr.s_addr = htonl(INADDR_ANY);

        int sfd = socket(AF_INET, SOCK_STREAM, 0);
        if (sfd < 0)
            FATAL("socket");
        else
        {
            int option = 1;
            setsockopt(sfd, SOL_SOCKET, SO_REUSEADDR, &option, sizeof(option));
            if ((bind(sfd,(struct sockaddr*)&my_addr,sizeof(struct sockaddr_in))) < 0)
                FATAL("bind");
            else
            {
                if ((listen(sfd,BACKLOG)) < 0)
                    FATAL("listen");
                else
                {
                    struct sockaddr naddr;
                    socklen_t naddrlen;
                    printf("Accepting connections on: %d\n",ntohs(my_addr.sin_port));
                    int nfd = accept(sfd,&naddr,&naddrlen);
                    if (nfd < 0)
                        FATAL("accept");
                    else
                    {
                        printf("New connection accepted, socked: %d\n",nfd);
                        char buf[BUFSIZE];
                        int n;
                        while ((n = recv(nfd,buf,BUFSIZE,0)) != 0)
                        {
                            printf("%s",buf);
                            memset(buf,0,BUFSIZE);
                        }
                        close(nfd);
                    }
                }
            }
        }
    }
    else
        usage();
    return 0;
}
