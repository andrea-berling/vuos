/* Copyright 2008 Renzo Davoli for LWIPv6 documentation.
 * Licensed inder the GPLv2
 *
 * Minimal terminal emulator on a TCP socket
 */

#include <stdio.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define BUFSIZE 1024
char buf[BUFSIZE];

int main(int argc,char *argv[])
{
  struct sockaddr_in serv_addr;
  int fd;
  void *handle;
  struct stack *stack;
  struct netif *nif;

  memset((char *) &serv_addr,0,sizeof(serv_addr));
  serv_addr.sin_family      = AF_INET;
  serv_addr.sin_addr.s_addr = inet_addr(argv[1]);
  serv_addr.sin_port        = htons(atoi(argv[2]));

  /* create a TCP lwipv6 socket */
  if((fd=socket(PF_INET,SOCK_STREAM,0))<0) {
    perror("Socket opening error");
    exit(-1);
  }
  /* connect it to the address specified as argv[1] port argv[2] */
  if (connect(fd,(struct sockaddr *)(&serv_addr),sizeof(serv_addr)) < 0) {
    perror("Socket connecting error");
    exit(-1);
  }
  while(1) {
    fd_set rfds;
    int n;
    FD_ZERO(&rfds);
    FD_SET(STDIN_FILENO,&rfds);
    FD_SET(fd,&rfds);
    /* wait for input both from stdin and from the socket */
    select(fd+1,&rfds,NULL,NULL,NULL);
    /* copy data from the socket to stdout */
    if(FD_ISSET(fd,&rfds)) {
      if((n=read(fd,buf,BUFSIZE)) == 0) /* XXX Possible critical point, should I use read or recv? */
        exit(0);
      write(STDOUT_FILENO,buf,n);
    }
    /* copy data from stdin to the socket */
    if(FD_ISSET(STDIN_FILENO,&rfds)) {
      if((n=read(STDIN_FILENO,buf,BUFSIZE)) == 0)
        exit(0);
      write(fd,buf,n); /* XXX Possible critical point, should I use write or send? */
    }
  }
}
