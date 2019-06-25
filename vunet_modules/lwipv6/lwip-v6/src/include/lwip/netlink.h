/*   This is part of LWIPv6
 *   Developed for the Ale4NET project
 *   Application Level Environment for Networking
 *   
 *   Copyright 2004 Renzo Davoli University of Bologna - Italy
 *   
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License along
 *   with this program; if not, write to the Free Software Foundation, Inc.,
 *   51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA.
 */   

#ifndef _NETLINK_H__
#define _NETLINK_H__
#include "lwip/api.h"
#include "lwip/sockets.h"
#include "lwip/netlinkdefs.h"
#include "lwip/if.h"
#include <libnlq.h>

struct netconn *
netlink_open(struct stack *stack, int type,int proto);

int
netlink_accept(void *sock, struct sockaddr *addr, socklen_t *addrlen);

int
netlink_bind(void *sock, struct sockaddr *name, socklen_t namelen);

int
netlink_close(void *sock);

int
netlink_connect(void *sock, struct sockaddr *name, socklen_t namelen);

int
netlink_recvfrom(void *sock, void *mem, int len, unsigned int flags,
        struct sockaddr *from, socklen_t *fromlen, int efd);

int
netlink_send(void *sock, void *data, int size, unsigned int flags, int efd);

int
netlink_sendto(void *sock, void *data, int size, unsigned int flags,
       struct sockaddr *to, socklen_t tolen, int efd);

int
netlink_getsockname (void *sock, struct sockaddr *name, socklen_t *namelen);

int 
netlink_getsockopt (void *sock, int level, int optname, void *optval, socklen_t *optlen);

int 
netlink_setsockopt (void *sock, int level, int optname, const void *optval, socklen_t optlen);

/* CONSTANT DEFINITION */

#if LWIP_NL

void netlink_addanswer(void *buf,int *offset,void *in,int len);
int mask2prefix (struct ip_addr *netmask);
void prefix2mask(int prefix,struct ip_addr *netmask);
void netlink_ackerror(void *msg,int ackerr,void *buf,int *offset);

//void netif_netlink_adddellink(struct stack *stack, struct nlmsghdr *msg, void * buf,int *offset);
//void netif_netlink_getlink(struct stack *stack, struct nlmsghdr *msg, void * buf,int *offset);

    /* LINK PROTOCOL HANDLERS */
void *netif_netlink_searchlink(struct nlmsghdr *msg, struct nlattr **attr, void *stackinfo);
int netif_netlink_getlink(void *entry, struct nlmsghdr *msg, struct nlattr **attr, struct nlq_msg
        **reply_msgq, void *stackinfo);
int netif_netlink_addlink(struct nlmsghdr *msg, struct nlattr **attr, void *stackinfo);
int netif_netlink_dellink(void *entry, struct nlmsghdr *msg, struct nlattr **attr, void *stackinfo);
int netif_netlink_setlink(void *entry, struct nlmsghdr *msg, struct nlattr **attr, void *stackinfo);

    /* ADDR PROTOCOL HANDLERS */

void *netif_netlink_searchaddr(struct nlmsghdr *msg, struct nlattr **attr, void *stackinfo);
int netif_netlink_getaddr(void *entry, struct nlmsghdr *msg, struct nlattr **attr, struct nlq_msg
        **reply_msgq, void *stackinfo);
int netif_netlink_addaddr(struct nlmsghdr *msg, struct nlattr **attr, void *stackinfo);
int netif_netlink_deladdr(void *entry, struct nlmsghdr *msg, struct nlattr **attr, void *stackinfo);

    /* ROUTE PROTOCOL HANDLERS */

void *ip_route_netlink_searchroute(struct nlmsghdr *msg, struct nlattr **attr, void *stackinfo);
int ip_route_netlink_getroute(void *entry, struct nlmsghdr *msg, struct nlattr **attr, struct nlq_msg
        **reply_msgq, void *stackinfo);
int ip_route_netlink_addroute(struct nlmsghdr *msg, struct nlattr **attr, void *stackinfo);
int ip_route_netlink_delroute(void *entry, struct nlmsghdr *msg, struct nlattr **attr, void *stackinfo);

//void netif_netlink_adddeladdr(struct stack *stack, struct nlmsghdr *msg, void * buf, int *offset);
//void netif_netlink_getaddr(struct stack *stack, struct nlmsghdr *msg, void * buf, int *offset);

//void ip_route_netlink_adddelroute(struct stack *stack, struct nlmsghdr *msg, void * buf, int *offset);
//void ip_route_netlink_getroute(struct stack *stack, struct nlmsghdr *msg, void * buf, int *offset);
#endif


#endif
