/*   This is part of LWIPv6
 *   Developed for the Ale4NET project
 *   Application Level Environment for Networking
 *   
 *   Copyright 2004,2008,2011 Renzo Davoli University of Bologna - Italy
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
/*
 * Copyright (c) 2001-2004 Swedish Institute of Computer Science.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT
 * SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT
 * OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
 * IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY
 * OF SUCH DAMAGE.
 *
 * This file is part of the lwIP TCP/IP stack.
 *
 * Author: Adam Dunkels <adam@sics.se>
 *
 * Improved by Marc Boucher <marc@mbsi.ca> and David Haas <dhaas@alum.rpi.edu>
 *
 */

#include <linux/limits.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/select.h>
#include <fcntl.h>
#include <unistd.h>
#include <limits.h>
#include <poll.h>
#include <vpoll.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>

#include "lwip/opt.h"
#include "lwip/api.h"
#include "lwip/arch.h"
#include "lwip/sys.h"
#include "lwip/mem.h"

#define LWIP_TIMEVAL_PRIVATE
#include "lwip/sockets.h"

#include "lwip/tcpip.h"

#if LWIP_NL
#include "lwip/netlink.h"
#endif

#if LWIP_PACKET
///#include <netpacket/packet.h>
#include "lwip/packet.h"
#endif


#include "lwip/native_syscalls.h"
#define NUM_SOCKETS MEMP_NUM_NETCONN


#define SOCK_IP64_CONV(ipaddr, ip4)  do { \
	(ipaddr)->addr[0] = 0; \
	(ipaddr)->addr[1] = 0; \
	(ipaddr)->addr[2] =  IP64_PREFIX; \
	memcpy(&((ipaddr)->addr[3]),(ip4),sizeof(struct ip4_addr)); } while (0)


#define SOCK_IP46_CONV(ip4, ipaddr)  (memcpy((ip4),&((ipaddr)->addr[3]),sizeof(struct ip4_addr)))
int _nofdfake = 0;

#ifdef LWIP_DEBUG
static char *domain_name(int domain) {
	switch (domain) {
		case PF_INET: return "PF_INET";
		case PF_INET6: return "PF_INET6";
#if LWIP_NL
		case PF_NETLINK: return "PF_NETLINK";
#endif
#if LWIP_PACKET
		case PF_PACKET: return "PF_PACKET";
#endif
	}
	return "UNKNOWN";
}
#endif

#define SOCKMAP_SIZE NUM_SOCKETS
static int *lwip_sockmap=NULL;
static int lwip_sockmap_len=0;

struct lwip_socket {
	u16_t family;
	struct netconn *conn;
	struct netbuf *lastdata;
	u16_t lastoffset;
	u16_t rcvevent;
	u16_t sendevent;
	u16_t  flags;
	int fdfake;
    int efd;
	int err;
};

#define SOCK_ROK(s) ((((s)->flags & O_ACCMODE) + 1) & 1)
#define SOCK_WOK(s) ((((s)->flags & O_ACCMODE) + 1) & 2)

static struct lwip_socket **sockets=NULL;
static int sockets_len=0;

#if LWIP_NL
#define NOT_CONN_SOCKET ((struct netconn *)(-1))
#endif

static sys_sem_t socksem = 0;
static sys_sem_t selectsem = 0;

static u16_t so_map[]={
	0, /*not used */
	SOF_DEBUG, /*SO_DEBUG*/
	SOF_REUSEADDR, /*SO_REUSEADDR*/
	0, /* SO_TYPE         */
	0, /* SO_ERROR        */
	SOF_DONTROUTE, /* SO_DONTROUTE    */
	SOF_BROADCAST, /* SO_BROADCAST    */
	0, /* SO_SNDBUF       */
	0, /* SO_RCVBUF       */
	SOF_KEEPALIVE, /* SO_KEEPALIVE    */
	SOF_OOBINLINE, /* SO_OOBINLINE    */
	0, /* SO_NO_CHECK     */
	0, /* SO_PRIORITY     */
	SOF_LINGER, /* SO_LINGER       */
	0, /* SO_BSDCOMPAT    */
	SOF_REUSEPORT, /* SO_REUSEPORT    */ 
	0, /* SO_RCVLOWAT     */
	0, /* SO_SNDLOWAT     */
	0, /* SO_RCVTIMEO     */
	0, /* SO_SNDTIMEO     */
	0, /* SO_PASSCRED     */
	0, /* SO_PEERCRED     */
	0, /* SO_SECURITY_AUTHENTICATION              */
	0, /* SO_SECURITY_ENCRYPTION_TRANSPORT        */
	0, /* SO_SECURITY_ENCRYPTION_NETWORK          */
	0, /* SO_BINDTODEVICE */
	0, /* SO_ATTACH_FILTER        */
	0, /* SO_DETACH_FILTER        */
	0, /* SO_PEERNAME             */
	0, /* SO_TIMESTAMP            */
	SOF_ACCEPTCONN /* SO_ACCEPTCONN           */
};

static void
event_callback(struct netconn *conn, enum netconn_evt evt, u16_t len);

static int err_to_errno_table[11] = {
	0,      /* ERR_OK    0      No error, everything OK. */
	ENOMEM,    /* ERR_MEM  -1      Out of memory error.     */
	ENOBUFS,    /* ERR_BUF  -2      Buffer error.            */
	ECONNABORTED,  /* ERR_ABRT -3      Connection aborted.      */
	ECONNRESET,    /* ERR_RST  -4      Connection reset.        */
	ESHUTDOWN,    /* ERR_CLSD -5      Connection closed.       */
	ENOTCONN,    /* ERR_CONN -6      Not connected.           */
	EINVAL,    /* ERR_VAL  -7      Illegal value.           */
	EIO,    /* ERR_ARG  -8      Illegal argument.        */
	EHOSTUNREACH,  /* ERR_RTE  -9      Routing problem.         */
	EADDRINUSE    /* ERR_USE  -10     Address in use.          */
};

#define ERRNO
#define err_to_errno(err) \
	(-(err) < (sizeof(err_to_errno_table)/sizeof(int))) ? \
err_to_errno_table[-(err)] : EIO

#ifdef ERRNO
int lwip_errno;
#define set_errno(err) do { \
	errno = (err); \
	lwip_errno = (err); \
} while (0)
#else
#define set_errno(err)
#endif

#define sock_set_errno(sk, e) do { \
	sk->err = (e); \
	set_errno(sk->err); \
} while (0)

long lwip_version()
{
	return 2;
}

static inline int get_lwip_sockmap(int s)
{
	if (s < 0 || s >= lwip_sockmap_len)
		return -1;
	else
		return lwip_sockmap[s];
}

static int set_lwip_sockmap(int s,short index)
{
	if (s >= lwip_sockmap_len) {
		int newlen;
		int *new_lwip_sockmap;
		if (lwip_sockmap_len == 0)
			newlen=sysconf(_SC_OPEN_MAX);
		else
			newlen=lwip_sockmap_len;
		if (s >= newlen)
			newlen=s+SOCKMAP_SIZE;
		if ((new_lwip_sockmap=mem_realloc(lwip_sockmap,newlen*sizeof(int))) == NULL)
			return -1;
		else {
			lwip_sockmap=new_lwip_sockmap;
			for (;lwip_sockmap_len<newlen;lwip_sockmap_len++)
				lwip_sockmap[lwip_sockmap_len]= -1;
		}
	}
	lwip_sockmap[s]=index;
}

	static struct lwip_socket *
get_socket(int s)
{
	struct lwip_socket *sock;
	int index=get_lwip_sockmap(s);

	if ((index < 0) || (index >= sockets_len)) {
		LWIP_DEBUGF(SOCKETS_DEBUG, ("get_socket(%d): invalid\n", s));
		set_errno(EBADF);
		return NULL;
	}

	sock = sockets[index];

	if (!sock->conn) {
		LWIP_DEBUGF(SOCKETS_DEBUG, ("get_socket(%d): not active\n", s));
		set_errno(EBADF);
		return NULL;
	}

	return sock;
}

extern int socket(int domain, int type, int protocol);
	static int
alloc_socket(struct netconn *newconn,u16_t family)
{
	int i,fd;
	struct lwip_socket *this;

	if (!socksem)
		socksem = sys_sem_new(1);

	this=mem_malloc(sizeof(struct lwip_socket));
	if (!this) {
		set_errno(ENOMEM);
		return -1;
	} else {
		this->family = family;
		this->conn = newconn;
		this->lastdata = NULL;
		this->lastoffset = 0;
		this->rcvevent = 0;
		this->sendevent = 1; /* TCP send buf is empty */
		this->flags = O_RDWR;
		this->err = 0;

		/* Protect socket array */
		sys_sem_wait(socksem);

		/* allocate a new socket identifier */
		for(i = 0; 1 ; ++i) {
			if (i >= sockets_len) {
				int newlen=sockets_len+NUM_SOCKETS;
				struct lwip_socket **newsockets;
				if ((newsockets=mem_realloc(sockets,newlen*(sizeof(struct lwip_socket *)))) == NULL) {
					mem_free(this);
					set_errno(ENOMEM);
					sys_sem_signal(socksem);
					return -1;
				}
				sockets=newsockets;
				for (;sockets_len<newlen;sockets_len++)
					sockets[sockets_len]=NULL;
			}
			if (!sockets[i]) {
				sockets[i]=this;
				sys_sem_signal(socksem);
				/*
				 * it is better to open a fake socket to satisfy S_ISSOCK()
				 */
				if (_nofdfake)
					fd=i;
				else
					fd=socket(PF_INET, SOCK_DGRAM, 0);
				if (fd < 0) {
					sockets[i]=NULL;
					mem_free(this);
					set_errno(EIO);
					return -1;
				} 
				this->fdfake=fd;
                this->efd = vpoll_create(0,EFD_CLOEXEC);
                vpoll_ctl(this->efd,VPOLL_CTL_ADDEVENTS,EPOLLOUT); /* TCP send buf is empty, ok to send */
				set_lwip_sockmap(fd,i);
				return fd;
			}
		}
		return -1;
	}
}


/* syncronous access to pcb data */

#define OPT_SETVALUE   1
#define OPT_GETVALUE   2
#define OPT_SETBITS    3
#define OPT_CLRBITS    4
#define OPT_GETMASKED  5

#define OPT_SO_OPTIONS 1
#define OPT_FLAGS      2
#define OPT_TOS        3
#define OPT_TTL        4
#define OPT_KEEPALIVE  5
#define OPT_CHECKSUMOFFSET  6

#define opfield(op,field) (((op) << 5) | (field))
struct opt_data {
	u16_t opfieldtag;
	u32_t *value;
};

static err_t sync_pcb_access(struct netconn *conn, void *arg)
{
	struct opt_data *data = arg;
	switch (data->opfieldtag) {
		case opfield(OPT_SETBITS, OPT_SO_OPTIONS): 
			conn->pcb.common->so_options |= *data->value; break;
		case opfield(OPT_CLRBITS, OPT_SO_OPTIONS): 
			conn->pcb.common->so_options &= ~(*data->value); break;
		case opfield(OPT_GETMASKED, OPT_SO_OPTIONS): 
			*data->value = conn->pcb.common->so_options & (*data->value); break;

		case opfield(OPT_SETBITS, OPT_FLAGS): 
			conn->pcb.common->so_options |= *data->value; break;
		case opfield(OPT_CLRBITS, OPT_FLAGS): 
			conn->pcb.common->so_options &= ~(*data->value); break;
		case opfield(OPT_GETMASKED, OPT_FLAGS): 
			*data->value = conn->pcb.common->so_options & (*data->value); break;

		case opfield(OPT_SETVALUE, OPT_TOS):
			conn->pcb.tcp->tos = (*data->value); break;
		case opfield(OPT_GETVALUE, OPT_TOS):
			(*data->value) = conn->pcb.tcp->tos; break;

		case opfield(OPT_SETVALUE, OPT_TTL):
			conn->pcb.tcp->ttl = (*data->value); break;
		case opfield(OPT_GETVALUE, OPT_TTL):
			(*data->value) = conn->pcb.tcp->ttl; break;

		case opfield(OPT_SETVALUE, OPT_KEEPALIVE):
			conn->pcb.tcp->keepalive = (*data->value); break;
		case opfield(OPT_GETVALUE, OPT_KEEPALIVE):
			(*data->value) = conn->pcb.tcp->keepalive; break;

		case opfield(OPT_SETVALUE, OPT_CHECKSUMOFFSET):
			conn->pcb.raw->so_options |= SOF_IPV6_CHECKSUM;
			conn->pcb.raw->checksumoffset = (*data->value); break;
	}
	return ERR_OK;
}

static u32_t pcb_access(struct netconn *conn, u8_t op, u8_t field, u32_t value)
{
	struct opt_data data = {
		.opfieldtag = opfield(op,field),
		.value = &value
	};
	netconn_callback(conn, sync_pcb_access, &data);
	return value;
}

/* ----- end of syncronous access to pcb data functions ---- */

	int
lwip_accept(int s, struct sockaddr *addr, socklen_t *addrlen)
{
	struct lwip_socket *sock;
	struct netconn *newconn;
	struct ip_addr naddr;
	u16_t port;
	int newsock;

	LWIP_DEBUGF(SOCKETS_DEBUG, ("lwip_accept(%d)...\n", s));
	sock = get_socket(s);
	if (!sock
#if LWIP_NL
			|| sock->family == PF_NETLINK
#endif
#if LWIP_PACKET
			|| sock->family == PF_PACKET
#endif
	   ) {
		set_errno(EBADF);
		return -1;
	}

	newconn = netconn_accept(sock->conn);

	/* get the IP address and port of the remote host */
	netconn_peer(newconn, &naddr, &port);

	if (addr != NULL) {
		if (sock->family == PF_INET) {
			struct sockaddr_in sin;
			memset(&sin, 0, sizeof(sin));
			sin.sin_family = sock->family;
			sin.sin_port = htons(port);
			/*memcpy(&(sin.sin_addr.s_addr),&(naddr.addr[3]),sizeof(sin.sin_addr.s_addr));*/
			SOCK_IP46_CONV(&(sin.sin_addr.s_addr),&(naddr));

			if (*addrlen > sizeof(sin))
				*addrlen = sizeof(sin);

			memcpy(addr, &sin, *addrlen);
		}           
		else {      
			struct sockaddr_in6 sin;
			memset(&sin, 0, sizeof(sin));
			sin.sin6_family = sock->family;
			sin.sin6_port = htons(port);
			memcpy(&(sin.sin6_addr),&(naddr.addr),sizeof(sin.sin6_addr));

			if (*addrlen > sizeof(sin))
				*addrlen = sizeof(sin);

			memcpy(addr, &sin, *addrlen);
		}
	}

	/* set by the EVT_ACCEPTPLUS event */
	newsock = newconn->socket;
	//printf("ACCEPT return %d was %d %p was %p\n",newsock,s,newconn,sock->conn);
	if (newsock == -1) {
		netconn_delete(newconn);
		sock_set_errno(sock, ENOBUFS);
		return -1;
	}

	LWIP_DEBUGF(SOCKETS_DEBUG, ("lwip_accept(%d) returning new sock=%d addr=", s, newsock));
	ip_addr_debug_print(SOCKETS_DEBUG, &naddr);
	LWIP_DEBUGF(SOCKETS_DEBUG, (" port=%u\n", port));

	sock_set_errno(sock, 0);
	return newsock;
}

	int
lwip_bind(int s, struct sockaddr *name, socklen_t namelen)
{
	struct lwip_socket *sock;
	struct ip_addr local_addr;
	u16_t local_port;
	err_t err;

	sock = get_socket(s);
	if (!sock) {
		set_errno(EBADF);
		return -1;
	}
#if LWIP_NL
	if (sock->family == PF_NETLINK) {
		return netlink_bind(sock->conn,name,namelen);
	} 
	else 
#endif
	{
#if LWIP_PACKET
		if (sock->family == PF_PACKET) {
			struct sockaddr_ll *packname=(struct sockaddr_ll *)name;
			SALL2IPADDR(*packname,local_addr);
			local_port=packname->sll_protocol;
		} else
#endif
			if (sock->family == PF_INET) {
				SOCK_IP64_CONV(&(local_addr),&(((struct sockaddr_in *)name)->sin_addr.s_addr));
				local_port = ((struct sockaddr_in *)name)->sin_port;
			}
			else {
				memcpy(&(local_addr.addr),&(((struct sockaddr_in6 *)name)->sin6_addr),sizeof(local_addr.addr));
				local_port = ((struct sockaddr_in6 *)name)->sin6_port;
			}

#if LWIP_CAPABILITIES
		struct stack *stack=netconn_stack(sock->conn);
		if (stack->stack_capfun && (stack->stack_capfun()&LWIP_CAP_NET_BIND_SERVICE) == 0) {
			set_errno(EPERM);
			return -1;
		}
#endif

		LWIP_DEBUGF(SOCKETS_DEBUG, ("lwip_bind(%d, addr=", s));
		ip_addr_debug_print(SOCKETS_DEBUG, &local_addr);
		LWIP_DEBUGF(SOCKETS_DEBUG, (" port=%u)\n", ntohs(local_port)));

		err = netconn_bind(sock->conn, &local_addr, ntohs(local_port));

		if (err != ERR_OK) {
			LWIP_DEBUGF(SOCKETS_DEBUG, ("lwip_bind(%d) failed, err=%d\n", s, err));
			sock_set_errno(sock, err_to_errno(err));
			return -1;
		}

		LWIP_DEBUGF(SOCKETS_DEBUG, ("lwip_bind(%d) succeeded\n", s));
		sock_set_errno(sock, 0);
		return 0;
	}
}

	int
lwip_close(int s)
{
	struct lwip_socket *sock;
	int err=0;

	LWIP_DEBUGF(SOCKETS_DEBUG, ("lwip_close(%d)\n", s));
	if (!socksem)
		socksem = sys_sem_new(1);

	/* We cannot allow multiple closes of the same socket. */
	sys_sem_wait(socksem);

	sock = get_socket(s);
	if (!sock) {
		sys_sem_signal(socksem);
		set_errno(EBADF);
		return -1;
	}

#if LWIP_NL
	if (sock->family == PF_NETLINK) {
		err=netlink_close(sock->conn);
		sock->conn = NULL;
	}
	else 
#endif
	{
		netconn_delete(sock->conn);
		if (sock->lastdata) {
			netbuf_delete(sock->lastdata);
		}
		sock->lastdata = NULL;
		sock->lastoffset = 0;
		sock->conn = NULL;
	}
	sockets[get_lwip_sockmap(s)]=NULL;
	if (! _nofdfake)
		close(sock->fdfake);
	set_lwip_sockmap(sock->fdfake, -1);
	sock_set_errno(sock, err);
    vpoll_close(sock->efd);
	mem_free(sock);
	sys_sem_signal(socksem);
	return err;
}

	int
lwip_connect(int s, struct sockaddr *name, socklen_t namelen)
{
	struct lwip_socket *sock;
	err_t err;

	sock = get_socket(s);
	if (!sock) {
		set_errno(EBADF);
		return -1;
	}

	if (((struct sockaddr_in *)name)->sin_family == PF_UNSPEC) {
		LWIP_DEBUGF(SOCKETS_DEBUG, ("lwip_connect(%d, PF_UNSPEC)\n", s));
		err = netconn_disconnect(sock->conn);
	}  
#if LWIP_NL
	else if (sock->family == PF_NETLINK)
		err=netlink_connect(sock->conn,name,namelen);
#endif
#if LWIP_PACKET
	//
#endif
	else 
	{
		struct ip_addr remote_addr;
		u16_t remote_port;

		if(sock->family == PF_INET) {
			SOCK_IP64_CONV(&(remote_addr),&(((struct sockaddr_in *)name)->sin_addr.s_addr));
			remote_port = ((struct sockaddr_in *)name)->sin_port;
		}
		else {
			memcpy(&(remote_addr.addr),&(((struct sockaddr_in6 *)name)->sin6_addr),sizeof(remote_addr.addr));
			remote_port = ((struct sockaddr_in6 *)name)->sin6_port;
		}

		LWIP_DEBUGF(SOCKETS_DEBUG, ("lwip_connect(%d, addr=", s));
		ip_addr_debug_print(SOCKETS_DEBUG, &remote_addr);
		LWIP_DEBUGF(SOCKETS_DEBUG, (" port=%u)\n", ntohs(remote_port)));

		err = netconn_connect(sock->conn, &remote_addr, ntohs(remote_port));
	}

	if (err != ERR_OK) {
		LWIP_DEBUGF(SOCKETS_DEBUG, ("lwip_connect(%d) failed, err=%d\n", s, err));
		sock_set_errno(sock, err_to_errno(err));
		return -1;
	}

	LWIP_DEBUGF(SOCKETS_DEBUG, ("lwip_connect(%d) succeeded\n", s));
	sock_set_errno(sock, 0);
	return 0;
}

	int
lwip_listen(int s, int backlog)
{
	struct lwip_socket *sock;
	err_t err;

	LWIP_DEBUGF(SOCKETS_DEBUG, ("lwip_listen(%d, backlog=%d)\n", s, backlog));
	sock = get_socket(s);
	if (!sock
#if LWIP_NL
			|| sock->family == PF_NETLINK
#endif
#if LWIP_PACKET
			|| sock->family == PF_PACKET
#endif
	   ) {
		set_errno(EBADF);
		return -1;
	}

	err = netconn_listen(sock->conn);

	if (err != ERR_OK) {
		LWIP_DEBUGF(SOCKETS_DEBUG, ("lwip_listen(%d) failed, err=%d\n", s, err));
		sock_set_errno(sock, err_to_errno(err));
		return -1;
	}

	sock_set_errno(sock, 0);
	return 0;
}

	ssize_t
lwip_recvfrom(int s, void *mem, int len, unsigned int flags,
		struct sockaddr *from, socklen_t *fromlen)
{
	struct lwip_socket *sock;
	struct netbuf *buf;
	u16_t buflen, copylen;
	struct ip_addr *addr;
	u16_t port;

	LWIP_DEBUGF(SOCKETS_DEBUG, ("lwip_recvfrom(%d, %p, %d, 0x%x, ..)\n", s, mem, len, flags));
	sock = get_socket(s);
	if (!sock) {
		set_errno(EBADF);
		return -1;
	}

#if LWIP_NL
	if (sock->family == PF_NETLINK) {
		return netlink_recvfrom(sock->conn,mem,len,flags,from,fromlen);
	} else
#endif
	{
		/* Check if there is data left from the last recv operation. */
		if (sock->lastdata) {
			buf = sock->lastdata;
		} else {
			/* If this is non-blocking call, then check first */
			if (((flags & MSG_DONTWAIT) || (sock->flags & O_NONBLOCK))
					&& !sock->rcvevent)
			{
				LWIP_DEBUGF(SOCKETS_DEBUG, ("lwip_recvfrom(%d): returning EWOULDBLOCK\n", s));
				sock_set_errno(sock, EWOULDBLOCK);
				return -1;
			}

			/*printf("netconn_recv %p R %d L %p S %d\n", sock->conn, sock->rcvevent, sock->lastdata, sock->sendevent);*/

			/* No data was left from the previous operation, so we try to get
			   some from the network. */
			buf = netconn_recv(sock->conn);

			if (!buf) {
				char *p=mem;
				/* We should really do some error checking here. */
				LWIP_DEBUGF(SOCKETS_DEBUG, ("lwip_recvfrom(%d): buf == NULL!\n", s));
				*p=0;
				sock_set_errno(sock, 0);
				return 0;
			}
		}

		buflen = netbuf_len(buf);

		buflen -= sock->lastoffset;

		if (len > buflen) {
			copylen = buflen;
		} else {
			copylen = len;
		}

		/* copy the contents of the received buffer into
		   the supplied memory pointer mem */
		netbuf_copy_partial(buf, mem, copylen, sock->lastoffset);

		/* Check to see from where the data was. */
		if (from && fromlen) {
			if (sock->family == PF_INET) {
				struct sockaddr_in sin;

				addr = netbuf_fromaddr(buf);
				port = netbuf_fromport(buf);

				memset(&sin, 0, sizeof(sin));
				/*sin.sin_len = sizeof(sin);*/
				sin.sin_family = PF_INET;
				sin.sin_port = htons(port);
				SOCK_IP46_CONV(&(sin.sin_addr.s_addr),addr);

				if (*fromlen > sizeof(sin))
					*fromlen = sizeof(sin);

				memcpy(from, &sin, *fromlen);
			}
			else if (sock->family == PF_INET6) {
				struct sockaddr_in6 sin;

				addr = netbuf_fromaddr(buf);
				port = netbuf_fromport(buf);

				memset(&sin, 0, sizeof(sin));
				sin.sin6_family = PF_INET6;
				sin.sin6_port = htons(port);
				memcpy(&(sin.sin6_addr),&(addr->addr),sizeof(sin.sin6_addr));

				if (*fromlen > sizeof(sin))
					*fromlen = sizeof(sin);

				memcpy(from, &sin, *fromlen);
			}
#if LWIP_PACKET
			else if (sock->family == PF_PACKET) {
				struct sockaddr_ll sll;

				addr = netbuf_fromaddr(buf);
				port = netbuf_fromport(buf);

				memset(&sll, 0, sizeof(sll));
				IPADDR2SALL(*addr,sll);
				sll.sll_protocol = htons(port);

				if (*fromlen > sizeof(sll))
					*fromlen = sizeof(sll);

				memcpy(from, &sll, *fromlen);
			}
#endif

			LWIP_DEBUGF(SOCKETS_DEBUG, ("lwip_recvfrom(%d): addr=", s));
			ip_addr_debug_print(SOCKETS_DEBUG, addr);
			LWIP_DEBUGF(SOCKETS_DEBUG, (" port=%u len=%u\n", port, copylen));
		} else {
#if SOCKETS_DEBUG > 0
			addr = netbuf_fromaddr(buf);
			port = netbuf_fromport(buf);

			LWIP_DEBUGF(SOCKETS_DEBUG, ("lwip_recvfrom(%d): addr=", s));
			ip_addr_debug_print(SOCKETS_DEBUG, addr);
			LWIP_DEBUGF(SOCKETS_DEBUG, (" port=%u len=%u\n", port, copylen));
#endif
		}

		if (flags & MSG_PEEK) {
			sock->lastdata = buf;
			/* lastoffset does not change, usually it is 0 and it keeps its value */
		}
		/* If this is a TCP socket, check if there is data left in the
		   buffer. If so, it should be saved in the sock structure for next
		   time around. */
		else if (netconn_type(sock->conn) == NETCONN_TCP && buflen - copylen > 0) {
			sock->lastdata = buf;
			sock->lastoffset += copylen;
		} else {
			sock->lastdata = NULL;
			sock->lastoffset = 0;
			netbuf_delete(buf);
		}

		sock_set_errno(sock, 0);
		if (flags & MSG_TRUNC) 
			return buflen;
		else
			return copylen;
	}
}

	ssize_t
lwip_read(int s, void *mem, int len)
{
	return lwip_recvfrom(s, mem, len, 0, NULL, NULL);
}

	ssize_t
lwip_recv(int s, void *mem, int len, unsigned int flags)
{
	return lwip_recvfrom(s, mem, len, flags, NULL, NULL);
}

ssize_t lwip_recvmsg(int fd, struct msghdr *msg, int flags)
{
	msg->msg_controllen=0;
	if (msg->msg_iovlen == 1) {
		ssize_t ret=lwip_recvfrom(fd, msg->msg_iov->iov_base,msg->msg_iov->iov_len,flags,
				msg->msg_name,&(msg->msg_namelen));
		if (ret > msg->msg_iov->iov_len) 
			msg->msg_flags |= MSG_TRUNC;
		return ret;

	} else {
		struct iovec *msg_iov;
		size_t msg_iovlen;
		unsigned int i,totalsize;
		size_t size;
		char *lbuf;
		msg_iov=msg->msg_iov;
		msg_iovlen=msg->msg_iovlen;
		for (i=0,totalsize=0;i<msg_iovlen;i++)
			totalsize += msg_iov[i].iov_len;
		lbuf=alloca(totalsize);
		size=lwip_recvfrom(fd, lbuf, totalsize, flags, msg->msg_name,&(msg->msg_namelen));
		if (size > totalsize)
			msg->msg_flags |= MSG_TRUNC;
		for (i=0;size > 0 && i<msg_iovlen;i++) {
			int qty=(size > msg_iov[i].iov_len)?msg_iov[i].iov_len:size;
			memcpy(msg_iov[i].iov_base,lbuf,qty);
			lbuf+=qty;
			size-=qty;
		}
		return size;
	}
}

	ssize_t
lwip_send(int s, void *data, int size, unsigned int flags)
{
	struct lwip_socket *sock;
	struct netbuf *buf;
	err_t err;

	/* FIX: handle EWOULDBLOCK in the right way. POSIX write()
	   blocks on a socket until all input data is written. 
	   Only with EWOULDBLOCK, input data and written data can be of
	   different sizes */

	LWIP_DEBUGF(SOCKETS_DEBUG, ("lwip_send(%d, data=%p, size=%d, flags=0x%x)\n", s, data, size, flags));

	sock = get_socket(s);
	if (!sock) {
		set_errno(EBADF);
		return -1;
	}

#if LWIP_NL
	if (sock->family == PF_NETLINK)  {
		return netlink_send(sock->conn,data,size,flags);
	}
	else 
#endif
	{
		/*netconn parms are u16*/
		if (size > USHRT_MAX) size=USHRT_MAX;
		switch (netconn_type(sock->conn)) {
			case NETCONN_RAW:
			case NETCONN_UDP:
			case NETCONN_UDPLITE:
#if LWIP_PACKET
			case NETCONN_PACKET_RAW:
			case NETCONN_PACKET_DGRAM:
#endif
				/* create a buffer */
				buf = netbuf_new();

				if (!buf) {
					LWIP_DEBUGF(SOCKETS_DEBUG, ("lwip_send(%d) ENOBUFS\n", s));
					sock_set_errno(sock, ENOBUFS);
					return -1;
				}

				/* make the buffer point to the data that should
				   be sent */
				netbuf_ref(buf, data, size);

				/* send the data */
				err = netconn_send(sock->conn, buf);

				/* deallocated the buffer */
				netbuf_delete(buf);
				break;
			case NETCONN_TCP:
				err = netconn_write(sock->conn, data, size, NETCONN_COPY);
				break;
			default:
				err = ERR_ARG;
				break;
		}
		if (err != ERR_OK) {
			LWIP_DEBUGF(SOCKETS_DEBUG, ("lwip_send(%d) err=%d\n", s, err));
			sock_set_errno(sock, err_to_errno(err));
			return -1;
		}

		LWIP_DEBUGF(SOCKETS_DEBUG, ("lwip_send(%d) ok size=%d\n", s, size));
		sock_set_errno(sock, 0);
		return size;
	}
}

	ssize_t
lwip_sendto(int s, void *data, int size, unsigned int flags,
		struct sockaddr *to, socklen_t tolen)
{
	struct lwip_socket *sock;
	struct ip_addr remote_addr, addr;
	u16_t remote_port, port;
	int ret,connected;

	sock = get_socket(s);
	if (!sock) {
		set_errno(EBADF);
		return -1;
	}

#if LWIP_NL
	if (sock->family == PF_NETLINK)  {
		return netlink_sendto(sock->conn,data,size,flags,to,tolen);
	}
	else 
#endif
	{
		/* get the peer if currently connected */
		connected = (netconn_peer(sock->conn, &addr, &port) == ERR_OK);

		if (tolen>0) {
			if (sock->family == PF_INET) {
				SOCK_IP64_CONV(&(remote_addr),&(((struct sockaddr_in *)to)->sin_addr.s_addr));
				remote_port = ((struct sockaddr_in *)to)->sin_port;
			}
			else if (sock->family == PF_INET6) {
				memcpy(&(remote_addr.addr),&(((struct sockaddr_in6 *)to)->sin6_addr),sizeof(remote_addr.addr));
				remote_port = ((struct sockaddr_in *)to)->sin_port;
			}
#if LWIP_PACKET
			else if (sock->family == PF_PACKET) {
				SALL2IPADDR(*(struct sockaddr_ll *)to,remote_addr);
				remote_port=(((struct sockaddr_ll *)to)->sll_protocol);
			}
#endif
			LWIP_DEBUGF(SOCKETS_DEBUG, ("lwip_sendto(%d, data=%p, size=%d, flags=0x%x to=", s, data, size, flags));
			ip_addr_debug_print(SOCKETS_DEBUG, &remote_addr);
			LWIP_DEBUGF(SOCKETS_DEBUG, (" port=%u\n", ntohs(remote_port)));

			netconn_connect(sock->conn, &remote_addr, ntohs(remote_port));
		}

		ret = lwip_send(s, data, size, flags);

		/* reset the remote address and port number
		   of the connection */
		if (connected) {
			if (tolen>0) netconn_connect(sock->conn, &addr, port);
		} else
			netconn_disconnect(sock->conn);
		return ret;
	}
}

ssize_t lwip_sendmsg(int fd, struct msghdr *msg, int flags)
{
	msg->msg_controllen=0;
	if (msg->msg_iovlen == 1) {
		return lwip_sendto(fd, msg->msg_iov->iov_base,msg->msg_iov->iov_len,flags,
				msg->msg_name,msg->msg_namelen);
	} else {
		struct iovec *msg_iov;
		size_t msg_iovlen;
		unsigned int i,totalsize;
		size_t size;
		char *lbuf;
		msg_iov=msg->msg_iov;
		msg_iovlen=msg->msg_iovlen;
		for (i=0,totalsize=0;i<msg_iovlen;i++)
			totalsize += msg_iov[i].iov_len;
		for (i=0;size > 0 && i<msg_iovlen;i++) {
			int qty=msg_iov[i].iov_len;
			memcpy(lbuf,msg_iov[i].iov_base,qty);
			lbuf+=qty;
			size-=qty;
		}
		size=lwip_sendto(fd, lbuf, totalsize, flags, msg->msg_name,msg->msg_namelen);
		return size;
	}
}

	int
lwip_msocket(struct stack *stack, int domain, int type, int protocol)
{
	struct netconn *conn;
	int i;

    /* Temporary solution: ignore the SOCK_CLOEXEC flag in type */
    if (type & SOCK_CLOEXEC)
        type &= ~SOCK_CLOEXEC;

	if (stack==NULL) {
		set_errno(ENONET);
		return -1;
	}

	if (domain != PF_INET && domain != PF_INET6
#if LWIP_NL
			&& domain != PF_NETLINK
#endif
#if LWIP_PACKET
			&& domain != PF_PACKET
#endif
	   ) {
		set_errno(EAFNOSUPPORT);
		return -1;
	}
	
#if LWIP_CAPABILITIES
	if (domain == PF_PACKET ||
			(domain == PF_INET || domain == PF_INET6) && type == SOCK_RAW) {
		if (stack->stack_capfun && (stack->stack_capfun()&LWIP_CAP_NET_RAW)==0) {
			set_errno(EPERM);
			return -1;
		}
	}
#endif

	switch(domain) {
#if LWIP_NL
		case PF_NETLINK:
			switch (type) {
				case SOCK_RAW:
				case SOCK_DGRAM:
					if (protocol != 0) {
						set_errno(EINVAL);
						return -1;
					} else {
						LWIP_DEBUGF(SOCKETS_DEBUG, ("lwip_socket(%s,XXX, %d) = ", domain_name(domain), protocol));
						conn = netlink_open(stack, type, protocol);
					}
					break;
				default:
					set_errno(EINVAL);
					return -1;
			}
			break;
#endif /* LWIP_NL */

#if LWIP_PACKET
		case PF_PACKET:
			switch (type) {
				case SOCK_RAW:
					conn = netconn_new_with_proto_and_callback(stack, NETCONN_PACKET_RAW, protocol, event_callback);
					LWIP_DEBUGF(SOCKETS_DEBUG, ("lwip_socket(%s, SOCK_RAW, %d) = ", domain_name(domain), protocol));
					break;
				case SOCK_DGRAM:
					conn = netconn_new_with_proto_and_callback(stack, NETCONN_PACKET_DGRAM, protocol, event_callback);
					LWIP_DEBUGF(SOCKETS_DEBUG, ("lwip_socket(%s, SOCK_DGRAM, %d) = ", domain_name(domain), protocol));
					break;
				default:
					LWIP_DEBUGF(SOCKETS_DEBUG, ("lwip_socket(%d, %d/UNKNOWN, %d) = -1\n", domain, type, protocol));
					set_errno(EINVAL);
					return -1;
			}
			break;
#endif /* LWIP_PACKET */

		case PF_INET:
		case PF_INET6:

			/* create a netconn */
			switch (type) {
				case SOCK_RAW:
					conn = netconn_new_with_proto_and_callback(stack, NETCONN_RAW, protocol, event_callback);
					LWIP_DEBUGF(SOCKETS_DEBUG, ("lwip_socket(%s, SOCK_RAW, %d) = ", domain_name(domain), protocol));
					break;
				case SOCK_DGRAM:
					conn = netconn_new_with_callback(stack, NETCONN_UDP, event_callback);
					LWIP_DEBUGF(SOCKETS_DEBUG, ("lwip_socket(%s, SOCK_DGRAM, %d) = ", domain_name(domain), protocol));
					break;
				case SOCK_STREAM:
					conn = netconn_new_with_callback(stack, NETCONN_TCP, event_callback);
					LWIP_DEBUGF(SOCKETS_DEBUG, ("lwip_socket(%s, SOCK_STREAM, %d) = ", domain_name(domain), protocol));
					break;
				default:
					LWIP_DEBUGF(SOCKETS_DEBUG, ("lwip_socket(%d, %d/UNKNOWN, %d) = -1\n", domain, type, protocol));
					set_errno(EINVAL);
					return -1;
			}
			break;
		default:
			LWIP_DEBUGF(SOCKETS_DEBUG, ("lwip_socket(%d/UNKNOWN, %d, %d) = -1\n", domain, type, protocol));
	}

	if (!conn) {
		LWIP_DEBUGF(SOCKETS_DEBUG, ("-1 / ENOBUFS (could not create netconn)\n"));
		set_errno(ENOBUFS);
		return -1;
	}

	i = alloc_socket(conn,domain);

	if (i == -1
#if LWIP_NL
			&& domain != PF_NETLINK
#endif
	   ) {
		netconn_delete(conn);
		set_errno(ENOBUFS);
		return -1;
	}
#if LWIP_NL
	if (domain != PF_NETLINK)
#endif
		conn->socket = i;
	LWIP_DEBUGF(SOCKETS_DEBUG, ("%d\n", i));
	set_errno(0);
	return i;
}

	int
lwip_socket(int domain, int type, int protocol)
{
	lwip_msocket(tcpip_stack_get(),domain,type,protocol);
}

	ssize_t
lwip_write(int s, void *data, int size)
{
	return lwip_send(s, data, size, 0);
}

#if 0
pfdset(int max, fd_set *fds)
{
	register int i;
	if (fds == NULL)
		printf("NULL");
	else
		for (i=0;i<max;i++)
			printf("%d|",FD_ISSET(i,fds));
	printf("\n");
}
#endif


struct um_sel_wait {
	void (* cb)(); 
	void *arg; 
	int fd; 
	int events;
	struct um_sel_wait *next;
};
static struct um_sel_wait *um_sel_head=NULL;

static void um_sel_add(void (* cb)(), void *arg, int fd, int events)
{
	struct um_sel_wait *new=(struct um_sel_wait *)mem_malloc(sizeof(struct um_sel_wait));
	//printf("UMSELECT ADD %d events %x arg %x\n",fd,events,arg);
	new->cb=cb;
	new->arg=arg;
	new->fd=fd;
	new->events=events;
	new->next=um_sel_head;
	um_sel_head=new;
}

/* recursive is simpler but maybe not optimized */
static struct um_sel_wait *um_sel_rec_del(struct um_sel_wait *p,void *arg,int fd)
{
	if (p==NULL) 
		return NULL;
	else {
		struct um_sel_wait *next=um_sel_rec_del(p->next,arg,fd);
		if (p->arg == arg && p->fd == fd) {
			mem_free(p);
			return(next);
		} else {
			p->next=next;
			return(p);
		}
	}
}

static void um_sel_del(void *arg, int fd)
{
	//printf("UMSELECT DEL arg %x\n",arg);
	um_sel_head=um_sel_rec_del(um_sel_head,arg,fd);
}

static struct um_sel_wait *um_sel_rec_signal(struct um_sel_wait *p,int fd, int events)
{
	if (p==NULL) 
		return NULL;
	else {
		if (fd == p->fd && (events & p->events) != 0) {
			/* found */
			struct um_sel_wait *next=um_sel_rec_del(p->next,p->arg,fd);
			//printf("UMSELECT SIGNALED %d\n",fd);
			p->cb(p->arg);
			mem_free(p);
			return um_sel_rec_signal(next,fd,events);
		} else {
			p->next=um_sel_rec_signal(p->next,fd,events);
			return p;
		}
	}
}

static void um_sel_signal(int fd, int events)
{
	//printf("UMSELECT SIGNAL fd %d events %x\n",fd,events);
	um_sel_head=um_sel_rec_signal(um_sel_head,fd,events);
}

int lwip_event_subscribe(void (* cb)(), void *arg, int fd, int events)
{
	struct lwip_socket *psock=get_socket(fd);
	int rv=0;
	//printf("UMSELECT REGISTER %s %d events %x arg %x psock %x\n",
	//(cb != NULL)?"REG" : "DEL", fd,events,arg,psock); 
	if (!selectsem)
		selectsem = sys_sem_new(1);
	sys_sem_wait(selectsem);
	if (psock) {
		//printf("R %d L %p S %d\n", psock->rcvevent, psock->lastdata, psock->sendevent);
#if LWIP_NL
		if (psock->family == PF_NETLINK)
			rv=events;
		else
#endif
			if ((rv= (events & POLLIN) * (psock->lastdata || psock->rcvevent || psock->conn->recv_avail) +
						(events & POLLOUT) * psock->sendevent) == 0 && cb != NULL)
				um_sel_add(cb,arg,fd,events);
	} 
	if (cb == NULL || rv>0)
		um_sel_del(arg,fd);
	//printf("UMSELECT REGISTER returns %x %p %d %d\n",rv,psock->lastdata , psock->rcvevent , psock->conn->recv_avail);
	sys_sem_signal(selectsem);
	return rv;
}

	static void
event_callback(struct netconn *conn, enum netconn_evt evt, u16_t len)
{
	int s;
	struct lwip_socket *sock;

	//printf("event_callback %p %d\n",conn,evt);
	/* Get socket */
	if (conn)
	{
		s = conn->socket;
		if (s < 0)
		{
			/* This should never happen! */
			printf("----socket hack already needed %d\n",conn->socket);
			return;
		}
		sock = get_socket(s);
		//printf("event_callback %p %d %d\n",conn,evt,s);
		if (!sock)
			return;
		if (evt == NETCONN_EVT_ACCEPTPLUS) {
			int newsock;
			newsock = alloc_socket(conn,sock->family);
			if (newsock >= 0) {
				sock = get_socket(newsock);
				sock->rcvevent =0;
			}
			conn->socket = newsock;
			//printf("NETCONN_EVT_ACCEPTPLUS %p %d \n",conn,newsock);
			return;
		}
	}
	else
		return;

	if (!selectsem)
		selectsem = sys_sem_new(1);

	sys_sem_wait(selectsem);
	/* Set event as required */
	switch (evt)
	{
		case NETCONN_EVT_RCVPLUS:
			sock->rcvevent++;
			break;
		case NETCONN_EVT_RCVMINUS:
			sock->rcvevent--;
			break;
		case NETCONN_EVT_SENDPLUS:
			sock->sendevent = 1;
			break;
		case NETCONN_EVT_SENDMINUS:
			sock->sendevent = 0;
			break;
	}
	//um_sel_signal(sock->fdfake, );

    int events = EPOLLIN * (sock->rcvevent || sock->lastdata || sock->conn->recv_avail) + EPOLLOUT *
        sock->sendevent;
    vpoll_ctl(sock->efd,VPOLL_CTL_SETEVENTS,events);
    
	//printf("EVENT fd %d(%d) R%d S%d\n",s,evt,sock->rcvevent,sock->sendevent);
	sys_sem_signal(selectsem);
}

	int
lwip_shutdown(int s, int how)
{
	struct lwip_socket *sock;
	int err=0;
	u16_t perm;

	LWIP_DEBUGF(SOCKETS_DEBUG, ("lwip_shutdown(%d, how=%d)\n", s, how));
	if (!socksem)
		socksem = sys_sem_new(1);

	sys_sem_wait(socksem);

	sock = get_socket(s);
	if (!sock) {
		sys_sem_signal(socksem);
		set_errno(EBADF);
		return -1;
	}

	perm=(sock->flags & O_ACCMODE)+1;
	perm &= ~((how & O_ACCMODE)+1);
	sock->flags = (sock->flags & ~O_ACCMODE) | ((perm - 1) & O_ACCMODE);

	sys_sem_signal(socksem);
	return 0;
}

	int
lwip_getpeername (int s, struct sockaddr *name, socklen_t *namelen)
{
	struct lwip_socket *sock;
	struct ip_addr naddr;
	u16_t port;

	sock = get_socket(s);
	if (!sock
#if LWIP_NL
			|| sock->family == PF_NETLINK
#endif
#if LWIP_PACKET
			|| sock->family == PF_PACKET
#endif
	   ) {
		set_errno(EBADF);
		return -1;
	}

	/* get the IP address and port of the remote host */
	netconn_peer(sock->conn, &naddr, &port);

	LWIP_DEBUGF(SOCKETS_DEBUG, ("lwip_getpeername(%d, addr=", s));
	ip_addr_debug_print(SOCKETS_DEBUG, &naddr);
	LWIP_DEBUGF(SOCKETS_DEBUG, (" port=%d)\n", port));

	if (sock->family == PF_INET) {
		struct sockaddr_in sin;
		memset(&sin, 0, sizeof(sin));
		sin.sin_family = PF_INET;
		sin.sin_port = htons(port);
		/*memcpy(&(sin.sin_addr.s_addr),&(naddr.addr),sizeof(sin.sin_addr.s_addr));*/
		SOCK_IP46_CONV(&(sin.sin_addr.s_addr),&(naddr));

		if (*namelen > sizeof(sin))
			*namelen = sizeof(sin);

		memcpy(name, &sin, *namelen);
	}
	else {
		struct sockaddr_in6 sin;
		memset(&sin, 0, sizeof(sin));
		sin.sin6_family = PF_INET6;
		sin.sin6_port = htons(port);
		memcpy(&(sin.sin6_addr),&(naddr.addr),sizeof(sin.sin6_addr));

		if (*namelen > sizeof(sin))
			*namelen = sizeof(sin);

		memcpy(name, &sin, *namelen);
	}

	sock_set_errno(sock, 0);

	return 0;
}

	int
lwip_getsockname (int s, struct sockaddr *name, socklen_t *namelen)
{
	struct lwip_socket *sock;
	struct ip_addr naddr;
	u16_t port;

	sock = get_socket(s);
	if (!sock) {
		set_errno(EBADF);
		return -1;
	}

#if LWIP_NL
	if (sock->family == PF_NETLINK) {
		return netlink_getsockname (sock->conn,name,namelen);
	}
	else 
#endif
	{
		int err;
		/* get the IP address and port of the remote host */
		err = netconn_addr(sock->conn, &naddr, &port);
		if (err != ERR_OK) {
			set_errno(EINVAL);
			return -1;
		}

		LWIP_DEBUGF(SOCKETS_DEBUG, ("lwip_getsockname(%d, addr=", s));
		ip_addr_debug_print(SOCKETS_DEBUG, &naddr);
		LWIP_DEBUGF(SOCKETS_DEBUG, (" port=%d)\n", port));

		if (sock->family == PF_INET) {
			struct sockaddr_in sin;
			memset(&sin, 0, sizeof(sin));
			sin.sin_family = PF_INET;
			sin.sin_port = htons(port);
			/*memcpy(&(sin.sin_addr.s_addr),&(naddr.addr),sizeof(sin.sin_addr.s_addr));*/
			SOCK_IP46_CONV(&(sin.sin_addr.s_addr),&naddr);

			if (*namelen > sizeof(sin))
				*namelen = sizeof(sin);

			memcpy(name, &sin, *namelen);
			/*printf("%x %d\n",sin.sin_addr.s_addr,*namelen);*/
		}
		else {
			struct sockaddr_in6 sin;
			memset(&sin, 0, sizeof(sin));
			sin.sin6_family = PF_INET6;
			sin.sin6_port = htons(port);
			memcpy(&(sin.sin6_addr),&naddr,sizeof(sin.sin6_addr));

			if (*namelen > sizeof(sin))
				*namelen = sizeof(sin);

			memcpy(name, &sin, *namelen);
		}

		sock_set_errno(sock, 0);
		return 0;
	}
}

	int
lwip_getsockopt (int s, int level, int optname, void *optval, socklen_t *optlen)
{
	int err = 0;
	struct lwip_socket *sock = get_socket(s);

	if (!sock) {
		set_errno(EBADF);
		return -1;
	}

	if( NULL == optval || NULL == optlen ) {
		sock_set_errno( sock, EFAULT );
		return -1;
	}

#if LWIP_NL
	if(sock->family == PF_NETLINK) {
		int err=netlink_getsockopt(sock->conn, level, optname, optval, optlen); 
		if (err != 0) {
			sock_set_errno(sock, err);
			return -1;
		} else
			return 0;
	}
#endif

	/* Do length and type checks for the various options first, to keep it readable. */
	switch( level ) {

		/* Level: SOL_SOCKET */
		case SOL_SOCKET:
			switch(optname) {

				case SO_ACCEPTCONN:
				case SO_BROADCAST:
					/* UNIMPL case SO_DEBUG: */
					/* UNIMPL case SO_DONTROUTE: */
				case SO_ERROR:
				case SO_KEEPALIVE:
					/* UNIMPL case SO_OOBINLINE: */
					/* UNINPL case SO_RCVBUF: */
					/* UNINPL case SO_SNDBUF: */
					/* FAKE SO_RCVBUF, SO_SNDBUF */
				case SO_RCVBUF:
				case SO_SNDBUF:
					/* UNIMPL case SO_RCVLOWAT: */
					/* UNIMPL case SO_SNDLOWAT: */
#if SO_REUSE
				case SO_REUSEADDR:
				case SO_REUSEPORT:
#endif /* SO_REUSE */
				case SO_TYPE:
					/* UNIMPL case SO_USELOOPBACK: */
					if( *optlen < sizeof(int) ) {
						err = EINVAL;
					}
					break;

				default:
					LWIP_DEBUGF(SOCKETS_DEBUG, ("lwip_getsockopt(%d, SOL_SOCKET, UNIMPL: optname=0x%x, ..)\n", s, optname));
					err = ENOPROTOOPT;
			}  /* switch */
			break;

			/* Level: IPPROTO_IP */
		case IPPROTO_IP:
			switch(optname) {
				case IP_HDRINCL:
					/* UNIMPL case IP_RCVDSTADDR: */
					/* UNIMPL case IP_RCVIF: */
				case IP_TTL:
				case IP_TOS:
					if( *optlen < sizeof(int) ) {
						err = EINVAL;
					}
					break;

				default:
					LWIP_DEBUGF(SOCKETS_DEBUG, ("lwip_getsockopt(%d, IPPROTO_IP, UNIMPL: optname=0x%x, ..)\n", s, optname));
					err = ENOPROTOOPT;
			}  /* switch */
			break;

			/* Level: IPPROTO_TCP */
		case IPPROTO_TCP:
			if( *optlen < sizeof(int) ) {
				err = EINVAL;
				break;
			}

			/* If this is no TCP socket, ignore any options. */
			if ( sock->conn->type != NETCONN_TCP ) return 0;

			switch( optname ) {
				case TCP_NODELAY:
				case TCP_KEEPALIVE:
					break;

				default:
					LWIP_DEBUGF(SOCKETS_DEBUG, ("lwip_getsockopt(%d, IPPROTO_TCP, UNIMPL: optname=0x%x, ..)\n", s, optname));
					err = ENOPROTOOPT;
			}  /* switch */
			break;

			/* UNDEFINED LEVEL */
		default:
			LWIP_DEBUGF(SOCKETS_DEBUG, ("lwip_getsockopt(%d, level=0x%x, UNIMPL: optname=0x%x, ..)\n", s, level, optname));
			err = ENOPROTOOPT;
	}  /* switch */


	if( 0 != err ) {
		sock_set_errno(sock, err);
		return -1;
	}



	/* Now do the actual option processing */

	switch(level) {

		/* Level: SOL_SOCKET */
		case SOL_SOCKET:
			switch( optname ) {

				/* The option flags */
				case SO_ACCEPTCONN:
				case SO_BROADCAST:
					/* UNIMPL case SO_DEBUG: */
					/* UNIMPL case SO_DONTROUTE: */
				case SO_KEEPALIVE:
					/* UNIMPL case SO_OOBINCLUDE: */
#if SO_REUSE
				case SO_REUSEADDR:
				case SO_REUSEPORT:
#endif /* SO_REUSE */
					/*case SO_USELOOPBACK: UNIMPL */
					//*(int*)optval = sock->conn->pcb.tcp->so_options & so_map[optname];
					*(int*)optval = pcb_access(sock->conn,OPT_GETMASKED,OPT_SO_OPTIONS,so_map[optname]);
					LWIP_DEBUGF(SOCKETS_DEBUG, ("lwip_getsockopt(%d, SOL_SOCKET, optname=0x%x, ..) = %s\n", s, optname, (*(int*)optval?"on":"off")));
					break;

				case SO_TYPE:
					switch (sock->conn->type) {
						case NETCONN_RAW:
							*(int*)optval = SOCK_RAW;
							break;
						case NETCONN_TCP:
							*(int*)optval = SOCK_STREAM;
							break;
						case NETCONN_UDP:
						case NETCONN_UDPLITE:
						case NETCONN_UDPNOCHKSUM:
							*(int*)optval = SOCK_DGRAM;
							break;
						default: /* unrecognized socket type */
							*(int*)optval = sock->conn->type;
							LWIP_DEBUGF(SOCKETS_DEBUG, ("lwip_getsockopt(%d, SOL_SOCKET, SO_TYPE): unrecognized socket type %d\n", s, *(int *)optval));
					}  /* switch */
					LWIP_DEBUGF(SOCKETS_DEBUG, ("lwip_getsockopt(%d, SOL_SOCKET, SO_TYPE) = %d\n", s, *(int *)optval));
					break;

				case SO_ERROR:
					*(int *)optval = sock->err;
					sock->err = 0;
					LWIP_DEBUGF(SOCKETS_DEBUG, ("lwip_getsockopt(%d, SOL_SOCKET, SO_ERROR) = %d\n", s, *(int *)optval));
					break;

					/*fake SO_RCVBUF, SO_SNDBUF, return the max value */
				case SO_RCVBUF:
				case SO_SNDBUF:
					*(int *)optval = 262144;
					break;
			}  /* switch */
			break;

			/* Level: IPPROTO_IP */
		case IPPROTO_IP:
			switch( optname ) {
				case IP_TTL:
					//*(int*)optval = sock->conn->pcb.tcp->ttl;
					*(int*)optval = pcb_access(sock->conn,OPT_GETVALUE,OPT_TTL,0);

					LWIP_DEBUGF(SOCKETS_DEBUG, ("lwip_getsockopt(%d, IPPROTO_IP, IP_TTL) = %d\n", s, *(int *)optval));
					break;
				case IP_TOS:
					//*(int*)optval = sock->conn->pcb.tcp->tos;
					*(int*)optval = pcb_access(sock->conn,OPT_GETVALUE,OPT_TOS,0);
					LWIP_DEBUGF(SOCKETS_DEBUG, ("lwip_getsockopt(%d, IPPROTO_IP, IP_TOS) = %d\n", s, *(int *)optval));
					break;
				case IP_HDRINCL:
					//*(int*)optval = (sock->conn->pcb.tcp->so_options & SOF_HDRINCL);
					*(int*)optval = pcb_access(sock->conn,OPT_GETMASKED,OPT_SO_OPTIONS,SOF_HDRINCL);
					break;
			}  /* switch */
			break;

			/* Level: IPPROTO_TCP */
		case IPPROTO_TCP:
			switch( optname ) {
				case TCP_NODELAY:
					//*(int*)optval = (sock->conn->pcb.tcp->flags & TF_NODELAY);
					*(int*)optval = pcb_access(sock->conn,OPT_GETMASKED,OPT_FLAGS,TF_NODELAY);
					LWIP_DEBUGF(SOCKETS_DEBUG, ("lwip_getsockopt(%d, IPPROTO_TCP, TCP_NODELAY) = %s\n", s, (*(int*)optval)?"on":"off") );
					break;
				case TCP_KEEPALIVE:
					//*(int*)optval = sock->conn->pcb.tcp->keepalive;
					*(int*)optval = pcb_access(sock->conn,OPT_GETVALUE,OPT_KEEPALIVE,0);
					LWIP_DEBUGF(SOCKETS_DEBUG, ("lwip_getsockopt(%d, IPPROTO_IP, TCP_KEEPALIVE) = %d\n", s, *(int *)optval));
					break;
			}  /* switch */
			break;
	}

	sock_set_errno(sock, err);
	return err ? -1 : 0;
}

	int
lwip_setsockopt (int s, int level, int optname, const void *optval, socklen_t optlen)
{
	struct lwip_socket *sock;
	int err = 0;

	sock = get_socket(s);
	if (!sock) {
		set_errno(EBADF);
		return -1;
	}
	if( NULL == optval ) {
		sock_set_errno( sock, EFAULT );
		/*printf("fault\n");*/
		return -1;
	}

#if LWIP_NL
	if(sock->family == PF_NETLINK) {
		int err=netlink_setsockopt(sock->conn, level, optname, optval, optlen);
		if (err != 0) {
			sock_set_errno(sock, err);
			return -1;
		} else
			return 0;
	}
#endif


	/* Do length and type checks for the various options first, to keep it readable. */
	switch( level ) {

		/* Level: SOL_SOCKET */
		case SOL_SOCKET:
			switch(optname) {

				case SO_BROADCAST:
					/* UNIMPL case SO_DEBUG: */
					/* UNIMPL case SO_DONTROUTE: */
				case SO_KEEPALIVE:
					/* UNIMPL case SO_OOBINLINE: */
					/* UNIMPL case SO_RCVBUF: */
					/* UNIMPL case SO_SNDBUF: */
					/* FAKE SO_SNDBUF, SO_RCVBUF, SO_TIMESTAMP */
				case SO_RCVBUF:
				case SO_SNDBUF:
				case SO_TIMESTAMP:
					/* UNIMPL case SO_RCVLOWAT: */
					/* UNIMPL case SO_SNDLOWAT: */
#if SO_REUSE
				case SO_REUSEADDR:
				case SO_REUSEPORT:
#endif /* SO_REUSE */
					/* UNIMPL case SO_USELOOPBACK: */
					if( optlen < sizeof(int) ) {
						err = EINVAL;
					}
					break;
					/*case SO_ATTACH_FILTER:
					  break;*/
				default:
					LWIP_DEBUGF(SOCKETS_DEBUG, ("lwip_setsockopt(%d, SOL_SOCKET, UNIMPL: optname=0x%x, ..)\n", s, optname));
					err = ENOPROTOOPT;
			}  /* switch */
			break;

			/* Level: IPPROTO_IP */
		case IPPROTO_IP:
			switch(optname) {
				case IP_HDRINCL:
					/* UNIMPL case IP_RCVDSTADDR: */
					/* UNIMPL case IP_RCVIF: */
				case IP_TTL:
				case IP_TOS:
					/* FAKE IP_MTU_DISCOVER */
				case IP_MTU_DISCOVER:
				case IP_RECVERR:
				case IP_RECVTTL:
				case IP_RECVTOS:				
					if( optlen < sizeof(int) ) {
						err = EINVAL;
					}
					break;
				default:
					LWIP_DEBUGF(SOCKETS_DEBUG, ("lwip_setsockopt(%d, IPPROTO_IP, UNIMPL: optname=0x%x, ..)\n", s, optname));
					err = ENOPROTOOPT;
			}  /* switch */
			break;

			/* Level: IPPROTO_TCP */
		case IPPROTO_TCP:
			if( optlen < sizeof(int) ) {
				err = EINVAL;
				break;
			}

			/* If this is not a TCP socket, ignore any options. */
			if ( sock->conn->type != NETCONN_TCP ) return 0;

			switch( optname ) {
				case TCP_NODELAY:
				case TCP_KEEPALIVE:
					break;

				default:
					LWIP_DEBUGF(SOCKETS_DEBUG, ("lwip_setsockopt(%d, IPPROTO_TCP, UNIMPL: optname=0x%x, ..)\n", s, optname));
					err = ENOPROTOOPT;
			}  /* switch */
			break;

			/* Level IPPROTO_IPV6 */      
		case IPPROTO_IPV6:
			switch( optname ) {
				case IPV6_HOPLIMIT:
				case IPV6_MULTICAST_HOPS:
				case IPV6_UNICAST_HOPS:
					break;
				default:
					printf("IPPROTO_IPV6 %d\n",optname);
					LWIP_DEBUGF(SOCKETS_DEBUG, ("lwip_setsockopt(%d, IPPROTO_IPV6, UNIMPL: optname=0x%x, ..)\n", s, optname));
					err = ENOPROTOOPT;
			}
			break;

			/* Level IPPROTO_ICMPV6 */      
		case IPPROTO_ICMPV6:
			switch( optname ) {
				case ICMPV6_FILTER:
					break;
				default:
					printf("IPPROTO_ICMPV6 %d\n",optname);
					LWIP_DEBUGF(SOCKETS_DEBUG, ("lwip_setsockopt(%d, IPPROTO_ICMPV6, UNIMPL: optname=0x%x, ..)\n", s, optname));
					err = ENOPROTOOPT;
			}
			break;

			/* Level IPPROTO_RAW */      
		case IPPROTO_RAW:
			switch( optname ) {
				case IPV6_CHECKSUM:
					if( optlen < sizeof(int) ) {
						err = EINVAL;
					}
					break;
				default:
					//printf("IPPROTO_RAW %d\n",optname);
					LWIP_DEBUGF(SOCKETS_DEBUG, ("lwip_setsockopt(%d, IPPROTO_RAW, UNIMPL: optname=0x%x, ..)\n", s, optname));
					err = ENOPROTOOPT;
			}
			break;

#if LWIP_PACKET
		case SOL_PACKET: 
			switch( optname ) { 
				case PACKET_ADD_MEMBERSHIP:
				case PACKET_DROP_MEMBERSHIP: 
					{
						const struct packet_mreq *pm = optval;
						if (optlen < sizeof(struct packet_mreq)) {
							err = EINVAL;
						} else {
							/* XXX Membership has not been managed yet */
							printf("PACKET_MEMBERSHIP %d %d %d %d\n",
									optname,pm->mr_ifindex,pm->mr_type,pm->mr_alen);
						}
					}
					break;
					//case PACKET_RECV_OUTPUT:
					//case PACKET_RX_RING:
					//case PACKET_STATISTICS:
				default:
					LWIP_DEBUGF(SOCKETS_DEBUG, ("lwip_setsockopt(%d, IPPROTO_RAW, UNIMPL: optname=0x%x, ..)\n", s, optname));
					err = ENOPROTOOPT;
					break;
			}
			break;
#endif

			/* UNDEFINED LEVEL */      
		default:
			LWIP_DEBUGF(SOCKETS_DEBUG, ("lwip_setsockopt(%d, level=0x%x, UNIMPL: optname=0x%x, ..)\n", s, level, optname));
			err = ENOPROTOOPT;
	}  /* switch */

	if( 0 != err ) {
		sock_set_errno(sock, err);
		return -1;
	}



	/* Now do the actual option processing */

	switch(level) {

		/* Level: SOL_SOCKET */
		case SOL_SOCKET:
			switch(optname) {

				/* The option flags */
				case SO_BROADCAST:
					/* UNIMPL case SO_DEBUG: */
					/* UNIMPL case SO_DONTROUTE: */
				case SO_KEEPALIVE:
					/* UNIMPL case SO_OOBINCLUDE: */
#if SO_REUSE
				case SO_REUSEADDR:
				case SO_REUSEPORT:
#endif /* SO_REUSE */
					/* UNIMPL case SO_USELOOPBACK: */
					if ( *(int*)optval ) {
						//sock->conn->pcb.tcp->so_options |= so_map[optname];
						pcb_access(sock->conn,OPT_SETBITS,OPT_SO_OPTIONS,so_map[optname]);
					} else {
						//sock->conn->pcb.tcp->so_options &= ~(so_map[optname]);
						pcb_access(sock->conn,OPT_CLRBITS,OPT_SO_OPTIONS,so_map[optname]);
					}
					LWIP_DEBUGF(SOCKETS_DEBUG, ("lwip_setsockopt(%d, SOL_SOCKET, optname=0x%x, ..) -> %s\n", s, optname, (*(int*)optval?"on":"off")));
					break;
			}  /* switch */
			break;

			/* Level: IPPROTO_IP */
		case IPPROTO_IP:
			switch( optname ) {
				case IP_TTL:
					//sock->conn->pcb.tcp->ttl = (u8_t)(*(int*)optval);
					pcb_access(sock->conn,OPT_SETVALUE,OPT_TTL,(*(int*)optval));
					LWIP_DEBUGF(SOCKETS_DEBUG, ("lwip_setsockopt(%d, IPPROTO_IP, IP_TTL, ..) -> %u\n", s, sock->conn->pcb.tcp->ttl));
					break;
				case IP_TOS:
					//sock->conn->pcb.tcp->tos = (u8_t)(*(int*)optval);
					pcb_access(sock->conn,OPT_SETVALUE,OPT_TOS,(*(int*)optval));
					LWIP_DEBUGF(SOCKETS_DEBUG, ("lwip_setsockopt(%d, IPPROTO_IP, IP_TOS, ..)-> %u\n", s, sock->conn->pcb.tcp->tos));
					break;
				case IP_HDRINCL:
					if (*(int*)optval) 
						//sock->conn->pcb.tcp->so_options |= SOF_HDRINCL;
						pcb_access(sock->conn,OPT_SETBITS,OPT_SO_OPTIONS,SOF_HDRINCL);
					else
						//sock->conn->pcb.tcp->so_options &= ~SOF_HDRINCL;
						pcb_access(sock->conn,OPT_CLRBITS,OPT_SO_OPTIONS,SOF_HDRINCL);
					break;
			}  /* switch */
			break;

			/* Level: IPPROTO_TCP */
		case IPPROTO_TCP:
			switch( optname ) {
				case TCP_NODELAY:
					if ( *(int*)optval ) {
						//sock->conn->pcb.tcp->flags |= TF_NODELAY;
						pcb_access(sock->conn,OPT_SETBITS,OPT_FLAGS,TF_NODELAY);
					} else {
						//sock->conn->pcb.tcp->flags &= ~TF_NODELAY;
						pcb_access(sock->conn,OPT_CLRBITS,OPT_FLAGS,TF_NODELAY);
					}
					LWIP_DEBUGF(SOCKETS_DEBUG, ("lwip_setsockopt(%d, IPPROTO_TCP, TCP_NODELAY) -> %s\n", s, (*(int *)optval)?"on":"off") );
					break;
				case TCP_KEEPALIVE:
					//sock->conn->pcb.tcp->keepalive = (u32_t)(*(int*)optval);
					pcb_access(sock->conn,OPT_SETVALUE,OPT_KEEPALIVE,(u32_t)(*(int*)optval));
					LWIP_DEBUGF(SOCKETS_DEBUG, ("lwip_setsockopt(%d, IPPROTO_TCP, TCP_KEEPALIVE) -> %u\n", s, (int) sock->conn->pcb.tcp->keepalive));
					break;
			}  /* switch */

			/* Level IPPROTO_IPV6 */      
		case IPPROTO_IPV6:
			switch( optname ) {
				case IPV6_UNICAST_HOPS:
				case IPV6_MULTICAST_HOPS:
					/* TODO add a separate ttl for unicast */
					//sock->conn->pcb.tcp->ttl = (u8_t)(*(int*)optval);
					pcb_access(sock->conn,OPT_SETVALUE,OPT_TTL,(*(int*)optval));
					LWIP_DEBUGF(SOCKETS_DEBUG, ("lwip_setsockopt(%d, IPPROTO_IPV6, IPV6_HOPLIMIT, ..) -> %u\n", s, sock->conn->pcb.tcp->ttl));
					break;
					/* TODO IPV6_HOPLIMIT is a flag to allow packet to inspect
					 * the hop limit value */
				case IPV6_HOPLIMIT:
					break;
				default:
					break;
			}
			break;

			/* Level IPPROTO_ICMPV6 */      
		case IPPROTO_ICMPV6:
			switch( optname ) {
				default:
					break;
			}
			break;

			/* Level IPPROTO_RAW */      
		case IPPROTO_RAW:
			switch( optname ) {
				case IPV6_CHECKSUM:
					//sock->conn->pcb.raw->so_options |= SOF_IPV6_CHECKSUM;
					//sock->conn->pcb.raw->checksumoffset=*(int*)optval;
					pcb_access(sock->conn,OPT_SETVALUE,OPT_CHECKSUMOFFSET,*(int*)optval);
					break;
				default:
					break;
			}
			break;

	}  /* switch */

	sock_set_errno(sock, err);
	return err ? -1 : 0;
}

int multistack_cmd(int cmd, void *param);

int lwip_ioctl(int s, unsigned long cmd, void *argp)
{
	struct lwip_socket *sock = get_socket(s);
	struct stack *stack;
	int cap;

	if (!sock
#if LWIP_NL
			|| sock->family == PF_NETLINK
#endif
#ifdef LWIP_SOCKET
			|| sock->family == PF_SOCKET
#endif
	   ) {
		LWIP_DEBUGF(SOCKETS_DEBUG, ("lwip_ioctl(%d, %u,... ) BADF\n", s, cmd));
		set_errno(EBADF);
		return -1;
	}

	switch (cmd) {
		case FIONREAD:
			if (!argp) {
				sock_set_errno(sock, EINVAL);
				return -1;
			}

			*((u32_t*)argp) = sock->conn->recv_avail;

			LWIP_DEBUGF(SOCKETS_DEBUG, ("lwip_ioctl(%d, FIONREAD, %p) = %lu\n", s, argp, *((u32_t*)argp)));
			sock_set_errno(sock, 0);
			return 0;

		case FIONBIO:
			if (argp && *(u32_t*)argp)
				sock->flags |= O_NONBLOCK;
			else
				sock->flags &= ~O_NONBLOCK;
			LWIP_DEBUGF(SOCKETS_DEBUG, ("lwip_ioctl(%d, FIONBIO, %d)\n", s, !!(sock->flags & O_NONBLOCK)));
			sock_set_errno(sock, 0);
			return 0;

		case SIOCGIFTXQLEN: /* XXX hack */
			if (!argp) {
				sock_set_errno(sock, EINVAL);
				return -1;
			}

			*((u16_t*)argp) = 0;

			LWIP_DEBUGF(SOCKETS_DEBUG, ("lwip_ioctl(%d, SIOCGIFTXQLEN, %p) = %u\n", s, argp, *((u16_t*)argp)));
			sock_set_errno(sock, 0);
			return 0;

		case SIOCGSTAMP:
			{
				struct timezone tz;
				struct timeval tv;
				gettimeofday(&tv,&tz);
				memcpy(argp,&tv,sizeof(struct timeval));  
			}
			return 0;
		default:
			stack=netconn_stack(sock->conn);
#if LWIP_CAPABILITIES
			if (stack->stack_capfun)
				cap=stack->stack_capfun();
			else
				cap= ~0;
#endif
			if (cmd >= SIOCGIFNAME && cmd <= SIOCSIFTXQLEN) {
				int err;
				err=netif_ioctl(stack, cmd, argp
#if LWIP_CAPABILITIES
						,cap
#endif
						);
				sock_set_errno(sock, err);
				LWIP_DEBUGF(SOCKETS_DEBUG, ("lwip_ioctl(%d, SIO TO NETIF) ret=%d\n",s,err));
				if (err)
					return -1;
				else
					return 0;
			}
			else if (cmd >= SIOCDARP && cmd <= SIOCSARP) {
				int err=1;
				err=etharp_ioctl(stack, cmd, argp
#if LWIP_CAPABILITIES
						,cap
#endif
						);
				sock_set_errno(sock, err);
				LWIP_DEBUGF(SOCKETS_DEBUG, ("lwip_ioctl(%d, SIO TO NETIF) ret=%d\n",s,err));
				if (err)
					return -1;
				else
					return 0;
			}
			else {
				LWIP_DEBUGF(SOCKETS_DEBUG, ("lwip_ioctl(%d, UNIMPL: 0x%lx, %p)\n", s, cmd, argp));

				sock_set_errno(sock, ENOSYS); /* not yet implemented */

				return -1;
			}
	}
}

#ifdef __USE_GNU
#define FCNTL_SETFL_MASK (O_APPEND|O_ASYNC|O_DIRECT|O_NOATIME|O_NONBLOCK)
#else
#define FCNTL_SETFL_MASK (O_APPEND|O_ASYNC|O_NONBLOCK)
#endif
int lwip_fcntl64(int s, int cmd, long arg)
{
	struct lwip_socket *sock = get_socket(s);
	LWIP_DEBUGF(SOCKETS_DEBUG, ("lwip_fcntl(%d, %x)\n",s,cmd));

	if (!sock
#if LWIP_NL
			|| sock->family == PF_NETLINK
#endif
#ifdef LWIP_SOCKET
			|| sock->family == PF_SOCKET
#endif
	   ) {
		set_errno(EBADF);
		return -1;
	}

	switch (cmd) {
		case F_GETFL:
			return sock->flags;
		case F_SETFL:
			sock->flags = (sock->flags & ~FCNTL_SETFL_MASK) | (arg & FCNTL_SETFL_MASK);
			return 0;
		default:
			return -1;
	}
}

int lwip_fcntl(int s, int cmd, long arg)
{
	return lwip_fcntl64(s,cmd,arg);
}

static int fdsplit(int max, 
		fd_set *rfd,
		fd_set *wfd,
		fd_set *efd,
		fd_set *rlfd,
		fd_set *wlfd,
		fd_set *elfd,
		fd_set *rnfd,
		fd_set *wnfd,
		fd_set *enfd)
{
	int lcount=0;
	register int i;
	if (rfd)
		*rlfd=*rnfd=*rfd;
	else {
		FD_ZERO(rlfd);
		FD_ZERO(rnfd);
	}
	if (wfd)
		*wlfd=*wnfd=*wfd;
	else {
		FD_ZERO(wlfd);
		FD_ZERO(wnfd);
	}
	if (efd)
		*elfd=*enfd=*efd;
	else {
		FD_ZERO(elfd);
		FD_ZERO(enfd);
	}
	for (i=0;i<max;i++) {
		if (get_lwip_sockmap(i) >= 0) {
			if(FD_ISSET(i,rlfd) || FD_ISSET(i,wlfd) || FD_ISSET(i,elfd))
				lcount++;
			FD_CLR(i,rnfd);
			FD_CLR(i,wnfd);
			FD_CLR(i,enfd);
		} else 
		{
			FD_CLR(i,rlfd);
			FD_CLR(i,wlfd);
			FD_CLR(i,elfd);
		}
	}
	return lcount;
}


void lwip_pipecb(int *fdp)
{
	write(fdp[1],"\0",1);
}

/*
 * Tue 04 Jun 2019 11:05:49 PM CEST
 * Gist of how pselect works:
 *  - a pipe fdp is created
 *  - three sets of fds are created, equal to the passed parameters if not null and empty otherwise
 *  - for each fd in the range [0,maxfdp1-1] it checks if fd is a socket. If so, it checks in which
 *  sets it belongs, to determine which events to wait on. If fd was part of some sets,
 *  event_subscribe is used to check if some events already happened on fd, and saves this
 *  information in revents. It then clears fd from the writeset (dunno why)
 *  The callback passed to event_subscribe is used to write a single byte to fdp[1] (to unlock
 *  pselect later on)
 *  - the reading end of fdp is added to the readset
 *  - if fdp is out of range(maxfdp1), newmaxp1 is defined to be fdp[0]+1, or maxfdp1 otherwise
 *  - a "real" pselect is carried out on the three created sets. If some events already happened the
 *  waiting time is 0, otherwise it's the one passed as a parameter
 *  - when an event on a fd happens, the previously given callback writes a single '\0' byte to
 *  fdp[1], to unlock the pselect
 *  - after unlocking, for each fd in the range(maxfdp1) if there are new events for fd a counter
 *  is incremented. This happens whether fd is a socket or not. If fd is a socket and some events
 *  happened on fd, then an event_subscribe with a NULL cb is called to clear the previous callback
 *  registration
 *  - The pipe ends are closed and the number of events is finally returned
 * */

#define TS_TO_MS(x) ((x) ? ((x)->tv_sec*1000 + (x)->tv_nsec/1000000) : -1)

int interesting_fd(int fd, fd_set *readset, fd_set *writeset, fd_set *exceptset)
{
    return (readset && FD_ISSET(fd,readset)) || (writeset && FD_ISSET(fd,writeset)) || (exceptset &&
            FD_ISSET(fd,exceptset));
}

int lwip_pselect(int maxfdp1, fd_set *readset, fd_set *writeset, fd_set *exceptset,
		const struct timespec *timeout, const sigset_t *sigmask)
{
	int i;
	int rv;
	struct lwip_socket *p_sock;
    int epfd;
    struct epoll_event revents[maxfdp1];
    memset(revents,-1,maxfdp1*sizeof(struct epoll_event));
    epfd = epoll_create1(EPOLL_CLOEXEC);
    // Errors from epoll are not "translated" into errors for pselect. Should probably fix this
    if (epfd == -1)
        return -1;
    for (i=0;i<maxfdp1;i++) {
        struct epoll_event ev = {0};
        if (readset && FD_ISSET(i,readset)) ev.events |= EPOLLIN;
        if (writeset && FD_ISSET(i,writeset)) ev.events |= EPOLLOUT;
        if (exceptset && FD_ISSET(i,exceptset)) ev.events |= EPOLLPRI;
        if (ev.events)
        {
            int fd = i;
            ev.data.fd = fd;
            if ((p_sock=get_socket(i))!=NULL) 
                fd = p_sock->efd;
            if ((epoll_ctl(epfd, EPOLL_CTL_ADD, fd, &ev)) == -1)
                return -1;
        }
    }
    
    rv = epoll_pwait(epfd,revents,maxfdp1,TS_TO_MS(timeout),sigmask);

    if (rv == -1)
        return -1;

    int handled[maxfdp1];
    memset(handled,0,maxfdp1*sizeof(int));
	for (i=0;i<maxfdp1;i++) {
        int fd = revents[i].data.fd;
        if (fd > -1)
        {
            handled[fd] = 1;
            LWIP_DEBUGF(SOCKETS_DEBUG, ("Fd with event\n"));
            LWIP_DEBUGF(SOCKETS_DEBUG, ("i value: %d\n",i));
            LWIP_DEBUGF(SOCKETS_DEBUG, ("File descriptor number %d\n",fd));
            LWIP_DEBUGF(SOCKETS_DEBUG, ("EPOLLIN = %d\n",revents[i].events & EPOLLIN));
            LWIP_DEBUGF(SOCKETS_DEBUG, ("EPOLLOUT = %d\n",revents[i].events & EPOLLOUT));
            LWIP_DEBUGF(SOCKETS_DEBUG, ("EPOLLPRI = %d\n",revents[i].events & EPOLLPRI));
            if ((p_sock = get_socket(fd)) != NULL)
            {
                LWIP_DEBUGF(SOCKETS_DEBUG, ("It's a lwip_socket\n"));
                if (readset) 
                {
                    if (FD_ISSET(fd,readset) && !(revents[i].events & EPOLLIN))
                        FD_CLR(fd,readset);
                }
                if (writeset) 
                {
                    if (FD_ISSET(fd,writeset) && !(revents[i].events & EPOLLOUT))
                        FD_CLR(fd,writeset);
                }
                if (exceptset) 
                {
                    if (FD_ISSET(fd,exceptset) && !(revents[i].events & EPOLLPRI))
                        FD_CLR(fd,exceptset);
                }
            }
            else
            {
                LWIP_DEBUGF(SOCKETS_DEBUG, ("It's not a lwip_socket\n"));
                if (readset)
                {
                    if (FD_ISSET(fd,readset) && !(revents[i].events & EPOLLIN))
                        FD_CLR(fd,readset);
                }
                if (writeset)
                {
                    if (FD_ISSET(fd,writeset) && !(revents[i].events & EPOLLOUT))
                        FD_CLR(fd,writeset);
                }
                if (exceptset)
                {
                    if (FD_ISSET(fd,exceptset) && !(revents[i].events & EPOLLPRI))
                        FD_CLR(fd,exceptset);
                }
            }
        }
        if (interesting_fd(i,readset,writeset,exceptset) && !handled[i])
        {
            LWIP_DEBUGF(SOCKETS_DEBUG, ("Registered fd with no events\n"));
            LWIP_DEBUGF(SOCKETS_DEBUG, ("i value: %d\n",i));
            LWIP_DEBUGF(SOCKETS_DEBUG, ("EPOLLIN = %d\n",revents[i].events & EPOLLIN));
            LWIP_DEBUGF(SOCKETS_DEBUG, ("EPOLLOUT = %d\n",revents[i].events & EPOLLOUT));
            LWIP_DEBUGF(SOCKETS_DEBUG, ("EPOLLPRI = %d\n",revents[i].events & EPOLLPRI));
            if (readset && FD_ISSET(i,readset)) 
                FD_CLR(i,readset);
            if (writeset && FD_ISSET(i,writeset))
                FD_CLR(i,writeset);
            if (exceptset && FD_ISSET(i,exceptset))
                FD_CLR(i,exceptset);
        }
	}

    close(epfd);

	return rv;
}

int lwip_select(int maxfdp1, fd_set *readset, fd_set *writeset, fd_set *exceptset,
		struct timeval *timeout) 
{
	struct timespec *ptimeout;
	if (timeout) {
		ptimeout=alloca(sizeof(struct timespec));
		ptimeout->tv_sec=timeout->tv_sec;
		ptimeout->tv_nsec=timeout->tv_usec*1000;
	} else
		ptimeout=NULL;
	return lwip_pselect(maxfdp1,readset,writeset,exceptset,ptimeout,NULL);
}

static inline int pollrealfdcount(struct pollfd *fds, nfds_t nfds) {
	int i,count;
	for (i=count=0;i<nfds;i++) 
		if (get_lwip_sockmap(fds[i].fd) < 0)
			count++;
	return count;
}

static void splitpollfds(struct pollfd *fds, nfds_t nfds,struct pollfd *rfds,
		fd_set *rlfd, fd_set *wlfd, fd_set *elfd)
{
	int i,count;
	FD_ZERO(rlfd);
	FD_ZERO(wlfd);
	FD_ZERO(elfd);
	for (i=count=0;i<nfds;i++) {
		if (get_lwip_sockmap(fds[i].fd) < 0) {
			rfds[count]=fds[i];
			count++;
		} else {
			if (fds[i].events & (POLLIN | POLLHUP))
				FD_SET(fds[i].fd,rlfd);
			if (fds[i].events & POLLOUT)
				FD_SET(fds[i].fd,wlfd);
			if (fds[i].events & (POLLERR | POLLPRI))
				FD_SET(fds[i].fd,elfd);
		}
	}
}

static int lwip_ppollscan(struct pollfd *fds, nfds_t nfds)
{
	int i,count;
	for (i=count=0;i<nfds;i++) {
		struct lwip_socket *p_sock;
		p_sock = get_socket(fds[i].fd);
		if (p_sock) {
			if ((fds[i].events & (POLLIN | POLLHUP)) &&
					(p_sock->lastdata || p_sock->rcvevent || p_sock->conn->recv_avail))
				count++;
			else if ((fds[i].events & POLLOUT) && p_sock->sendevent)
				count++;
		}
	}
	return count;
}

static int lwip_pollmerge(struct pollfd *fds, nfds_t nfds, struct pollfd *rfds)
{
	int i,count,ri;
	for (i=ri=count=0;i<nfds;i++) {
		struct lwip_socket *p_sock;
		p_sock = get_socket(fds[i].fd);
		if (p_sock) {
			fds[i].revents=0;
			if ((fds[i].events & (POLLIN | POLLHUP)) &&
					(p_sock->lastdata || p_sock->rcvevent || p_sock->conn->recv_avail))
				fds[i].revents |= POLLIN;
			if ((fds[i].events & POLLOUT) && p_sock->sendevent)
				fds[i].revents |= POLLOUT;
		} else {
			if (fds[i].fd != rfds[ri].fd)
				printf("ERROR misalignment!\n");
			else {
				fds[i].revents=rfds[ri].revents;
				ri++;
			}
		}
		if (fds[i].revents)
			count++;
	}
	return count;
}

/*
 * Wed 05 Jun 2019 10:55:47 AM CEST
 * ppoll is implemented in a similar way to pselect, except that instead of adding the
 * reading end of fdp to the fds to be observed (which would require to clone the array or to modify
 * the array passed as an argument), a fd representing a socket in the fds array is substituted by
 * it and later restored
 * */

int lwip_ppoll(struct pollfd *fds, nfds_t nfds,
		const struct timespec *timeout, const sigset_t *sigmask) {
	int i,j;
	int rv;
	struct epoll_event *revents = alloca(nfds*sizeof(struct epoll_event));
    memset(revents,-1,nfds*sizeof(struct epoll_event));
    LWIP_DEBUGF(SOCKETS_DEBUG, ("revents[%d] = {fd: %d, events: %x}\n",0,revents[0].data.fd,revents[0].events));
    LWIP_DEBUGF(SOCKETS_DEBUG, ("revents[%d] = {fd: %d, events: %x}\n",1,revents[1].data.fd,revents[1].events));
    struct lwip_socket *p_sock;
    int epfd;
    epfd = epoll_create1(EPOLL_CLOEXEC);
    // Errors from epoll are not "translated" into errors for ppoll. Should probably fix this
    if (epfd < 0)
        return -1;
	for (i=0;i<nfds;i++) {
		if (fds[i].fd > -1 && fds[i].events) {
            struct epoll_event ev = {0};
            int fd = fds[i].fd;
            if ((p_sock=get_socket(fds[i].fd))!=NULL)
                fd = p_sock->efd;
			ev.data.fd = fd;
            ev.events = 0;
            if (fds[i].events & POLLIN)
                ev.events |= EPOLLIN;
            if (fds[i].events & POLLOUT)
                ev.events |= EPOLLOUT;
            if (fds[i].events & POLLPRI)
                ev.events |= EPOLLPRI;
            if ((epoll_ctl(epfd, EPOLL_CTL_ADD, fd, &ev)) == -1)
                return -1;
		}
	}

    rv = epoll_pwait(epfd,revents,nfds,TS_TO_MS(timeout),sigmask);

    if (rv < 0)
        return -1;
	for (i=0;i<nfds;i++) {
        LWIP_DEBUGF(SOCKETS_DEBUG, ("revents[%d] = {fd: %d, events: %x}\n",i,revents[i].data.fd,revents[i].events));
        int fd = fds[i].fd;
        if ((p_sock = get_socket(fds[i].fd)) != NULL)
            fd = p_sock->efd;
		if (fd > -1) {
            for (j=0;j<nfds;j++) {
                if (revents[j].data.fd == fd)
                {
                    if (revents[j].events & EPOLLIN)
                        fds[i].revents |= POLLIN;
                    if (revents[j].events & EPOLLOUT)
                        fds[i].revents |= POLLOUT;
                    if (revents[j].events & EPOLLPRI)
                        fds[i].revents |= POLLPRI;
                }
            }
        }
	}

    close(epfd);

	return rv;
}

int lwip_epoll_ctl(int epfd, int op, int fd, struct epoll_event *event)
{
    // Mon 10 Jun 2019 03:03:02 PM CEST
    // No check is made on whether event != NULL. Should probably change that
    if (epfd > -1 && fd > -1)
    {
        struct lwip_socket *p_sock = get_socket(fd);
        if (p_sock != NULL)
            fd = p_sock->efd;
        return epoll_ctl(epfd,op,fd,event);
    }
    else
    {
        set_errno(EBADF);
        return -1;
    }
}

int lwip_poll(struct pollfd *fds, nfds_t nfds, int timeout) {
	int rv;
	struct timespec *ptimeout;
	if (timeout>=0) {
		ptimeout=alloca(sizeof(struct timespec));
		ptimeout->tv_sec=timeout/1000;
		ptimeout->tv_nsec=(timeout%1000)*1000000;
	} else
		ptimeout=NULL;
	rv=lwip_ppoll(fds,nfds,ptimeout,NULL);
}

/* FIX: change implementations. Do not use a private buffer */
ssize_t lwip_writev(int s, struct iovec *vector, int count)
{
	ssize_t totsize=0;
	int i;
	ssize_t pos;
	char *temp_buf;
	ssize_t ret;

	/* Check for invalid parameter */
	if (count < 0 || count > UIO_MAXIOV) {
		set_errno(EINVAL);
		return -1;
	}

	/* FIX: check overflow of  totsize and set EINVAL */
	for (i=0; i<count; i++)
		totsize += vector[i].iov_len;

	LWIP_DEBUGF(SOCKETS_DEBUG, ("lwip_writev(%d, %p, %d), iovec totlen=$d\n", s, vector, count, totsize));


	if (totsize == 0)
		return 0;

	temp_buf = mem_malloc(totsize);
	if (temp_buf == NULL) {
		set_errno(ENOMEM);
		return -1;
	}

	/* Copy in iovec buffers in the private buffer */
	i = 0;
	pos = 0;
	while (pos < totsize) {
		memcpy( &temp_buf[pos], vector[i].iov_base, vector[i].iov_len);
		i++;
		pos += vector[i].iov_len;
	}

	ret = lwip_write(s, temp_buf, totsize);

	mem_free(temp_buf);

	return ret;
}

ssize_t lwip_readv(int s, struct iovec *vector, int count)
{
	ssize_t totsize=0;
	int i;
	ssize_t pos;
	char *temp_buf;
	ssize_t ret;

	/* Check for invalid parameter */
	if (count < 0 || count > UIO_MAXIOV) {
		set_errno(EINVAL);
		return -1;
	}

	/* FIX: check overflow of  totsize and set EINVAL */
	for (i=0; i<count; i++)
		totsize += vector[i].iov_len;

	LWIP_DEBUGF(SOCKETS_DEBUG, ("lwip_readv(%d, %p, %d), iovec totlen=$d\n", s, vector, count, totsize));

	if (totsize == 0)
		return 0;


	temp_buf = mem_malloc(totsize);
	if (temp_buf == NULL) {
		set_errno(ENOMEM);
		return -1;
	}

	ret = lwip_read(s, temp_buf, totsize);
	if (ret != -1) {
		i = 0;
		pos = 0;
		while (pos < ret) {
			memcpy( vector[i].iov_base, &temp_buf[pos], vector[i].iov_len);
			i++;
			pos += vector[i].iov_len;
		}
	}

	mem_free(temp_buf);

	return ret;
}

/*
 * Wed 05 Jun 2019 11:32:50 AM CEST
 * Plan of action:
 *  - implement pselect in a similar way to the one it is already implemented in, but with the
 *  following modifications:
 *      - instead of using a ppoll, a epoll fd epfd is created and used to wait on the various fds
 *      - each socket is associated with a eventfd (maybe using the fdfake field, which is already
 *      present in lwip_socket) on which events can be signaled using the vpoll API
 *      - for each fd, if an fd is just a normal fd no special treatment is need. If an fd
 *      represents a lwip socket, instead of adding the fd itself to epfd, the eventfd associated
 *      with is is added to epfd, along with the value of fd in the epoll_data data structure
 *      - epoll_wait is performed on epfd
 *      - upon unlocking, info about events is retrieved from epfd and used to return the right
 *      events and to count them
 *  - when is the epoll_wait call unlocked? When there is an event on the socket. As of right now,
 *  when this happens the um_sel_signal function is called, which in turn calls the callback which
 *  was registered with event_subscribe. Instead of doing that, we can just signal the eventfd
 *  associated with a socket using the vpoll API
 *  - implement ppoll analogously
 *  The following functions in the following files call the netconn callback:
 *      - api_lib:
            - netconn_accept
            - netconn_recv
        - api_msg:
            - recv_udp
            - recv_tcp
            - recv_raw
            - sent_tcp
            - err_tcp
            - accept_function
            - do_delconn
            - do_write
    However, it's probably not necessary to go and modify each one. The easiest thing would be to
    directly modify the event_callback function

 * Wed 05 Jun 2019 12:02:38 PM CEST
 *
 * Using this approach it's possible to also implement the epoll_ctl system call, which adds the
 * eventfd associated with a socket fd instead of the socket fd itself. However, this approach
 * requires to also implement the epoll_wait system call, so that the "return set" is fixed by
 * substituting the eventfds with the respective socket fds with the right events associated with
 * them (along with the data the caller passed, which should be probably saved in lwip_socket with a
 * dedicated field)
 * */
