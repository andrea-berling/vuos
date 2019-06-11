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
#include <lwipv6.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <poll.h>

#define BUFSIZE 1024
char buf[BUFSIZE];

int main(int argc,char *argv[])
{
  struct sockaddr_in serv_addr;
  int fd;
  void *handle;
  struct stack *stack;
  struct netif *nif;
  struct ip_addr addr;
  struct ip_addr mask;

#ifdef LWIPV6DL
  /* Run-time load the library (if requested) */
  if ((handle=loadlwipv6dl()) == NULL) {
    perror("LWIP lib not loaded");
    exit(-1);
  }
#endif
  /* define a new stack */
  if((stack=lwip_stack_new())==NULL){
    perror("Lwipstack not created");
    exit(-1);
  }
  /* add an interface */
  if((nif=lwip_tapif_add(stack,"tap0"))==NULL){
    perror("Interface not loaded");
    exit(-1);
  }
  /* set the local IP address of the interface */
  IP64_ADDR(&addr,192,168,0,150);
  IP64_MASKADDR(&mask,255,255,255,0);
  lwip_add_addr(nif,&addr,&mask);
  /* turn on the interface */
  lwip_ifup(nif);

  memset((char *) &serv_addr,0,sizeof(serv_addr));
  serv_addr.sin_family      = AF_INET;
  serv_addr.sin_addr.s_addr = inet_addr(argv[1]);
  serv_addr.sin_port        = htons(atoi(argv[2]));

  /* create a TCP lwipv6 socket */
  if((fd=lwip_msocket(stack,PF_INET,SOCK_STREAM,0))<0) {
    perror("Socket opening error");
    exit(-1);
  }
  /* connect it to the address specified as argv[1] port argv[2] */
  if (lwip_connect(fd,(struct sockaddr *)(&serv_addr),sizeof(serv_addr)) < 0) {
    perror("Socket connecting error");
    exit(-1);
  }
  while(1) {
    struct pollfd fds[2];
    memset(fds,0,2*sizeof(struct pollfd));
    int n;
    fds[0].fd = STDIN_FILENO;
    fds[0].events = POLLIN;
    fds[1].fd = fd;
    fds[1].events = POLLIN;
    /* wait for input both from stdin and from the socket */
    printf("Ready\n");
    lwip_poll(fds,2,-1);
    /* copy data from the socket to stdout */
    if(fds[1].revents & POLLIN) {
      if((n=lwip_read(fd,buf,BUFSIZE)) == 0)
        exit(0);
      write(STDOUT_FILENO,buf,n);
    }
    /* copy data from stdin to the socket */
    if(fds[0].revents & POLLIN) {
      if((n=read(STDIN_FILENO,buf,BUFSIZE)) == 0)
        exit(0);
      lwip_write(fd,buf,n);
    }
  }
}