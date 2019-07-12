#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <linux/net.h>
#include <linux/net.h>
#include <linux/sockios.h>
#include <linux/if.h>
#include <dlfcn.h>
#include <lwip/netif.h>
#include <lwip/ip_addr.h>
#include <lwip/netifapi.h>
#include <lwip/tcpip.h>
#include <lwip/err.h>
#include <lwip/ip4_addr.h>
#include <lwip/pbuf.h>
#include <vunet.h>
#include <fduserdata.h>
#include <vpoll.h>
#include <libnlq.h>
#include <linux/netlink.h>

#define DEBUG 1

#define NUM_SOCKETS MEMP_NUM_NETCONN
#define LIB_LWIP "liblwip.so"

#define lwip_socket_SYM 0
#define lwip_bind_SYM 1
#define lwip_connect_SYM 2
#define lwip_listen_SYM 3
#define lwip_accept_SYM 4
#define lwip_getsockname_SYM 5
#define lwip_getpeername_SYM 6
#define lwip_recvmsg_SYM 7
#define lwip_sendmsg_SYM 8
#define lwip_setsockopt_SYM 9
#define lwip_getsockopt_SYM 10
#define lwip_shutdown_SYM 11
#define lwip_ioctl_SYM 12
#define lwip_fcntl_SYM 13
#define lwip_close_SYM 14
#define netif_find_SYM 15
#define netif_get_by_index_SYM 16
#define sys_lock_tcpip_core_SYM 17
#define sys_unlock_tcpip_core_SYM 18
#define netif_list_SYM 19
#define netif_set_up_SYM 20
#define netif_set_down_SYM 21
#define netif_set_addr_SYM 22
#define tapif_init_SYM 23
#define netif_add_SYM 24
#define tcpip_input_SYM 25
#define tcpip_init_SYM 26
#define netif_remove_SYM 27
#define netif_ip6_addr_set_state_SYM 28
#define netif_add_ip6_address_SYM 29

const char* lwip_sym_names[] = {
    "lwip_socket",
    "lwip_bind",
    "lwip_connect",
    "lwip_listen",
    "lwip_accept",
    "lwip_getsockname",
    "lwip_getpeername",
    "lwip_recvmsg",
    "lwip_sendmsg",
    "lwip_setsockopt",
    "lwip_getsockopt",
    "lwip_shutdown",
    "lwip_ioctl",
    "lwip_fcntl",
    "lwip_close",
    "netif_find",
    "netif_get_by_index",
    "sys_lock_tcpip_core",
    "sys_unlock_tcpip_core",
    "netif_list",
    "netif_set_up",
    "netif_set_down",
    "netif_set_addr",
    "tapif_init",
    "netif_add",
    "tcpip_input",
    "tcpip_init",
    "netif_remove",
    "netif_ip6_addr_set_state",
    "netif_add_ip6_address"
};

#define SYM_NUM sizeof(lwip_sym_names)/sizeof(char*)

/* In this macro x is purposedly written without parentheses around it to permit a return statement
 with nothing as an argument (e.g. in void functions). Use carefully
 */
#define DL_ERROR(x) do {\
    fprintf(stderr,"vunetlwip.c, line:%d, %s\n",__LINE__,dlerror());\
    return x;\
    } while(0)

#define EFD_TBL_SIZE 64

#define RESOLVE_SYM(s,type,sd) ((type) ((sd)->lwipsymtab[s##_SYM]))

struct stack_data {
    void *handle;               // Handle to lwip.so symbols
    struct netif *netif;        // Network interface
    void * lwipsymtab[SYM_NUM]; // Lwip symbol table, to retrieve stack functions and variables
    FDUSERDATA *sockets_data;   // Used for event handling
};

struct fd_data {
    struct epoll_event ev;
    int fd;
    unsigned char is_netlink;
    struct nlq_msg *msgq;
};

static int vunetlwip_socket(int domain, int type, int protocol){
    struct stack_data *sd = vunet_get_private_data();
    int fd;
    int is_netlink = 0;
    int (*socket)(int,int,int);
    socket = RESOLVE_SYM(lwip_socket,int (*)(int,int,int),sd);
    if (domain != AF_NETLINK)
        fd = socket(domain,type,protocol);
    else
    {
        // Opening an unused "fake" socket, to get a valid fd that does not clash with the others
        fd = socket(AF_INET,SOCK_DGRAM,0);
        is_netlink = 1;
    }
    if (fd > -1)
    {
        struct fd_data *fdd = fduserdata_new(sd->sockets_data,fd,struct fd_data);
        if (!fdd) {errno = ENOMEM; return -1;}
        // XXX Should I use some particular flag?
        fdd->fd = vpoll_create(0,0);
        fdd->is_netlink = is_netlink;
        fdd->msgq = NULL;
        vpoll_ctl(fdd->fd,VPOLL_CTL_ADDEVENTS,EPOLLOUT); /* The socket is ready for packet sending */
        fduserdata_put(fdd);
        return fd;
    }
    else
        return -1;
}

static int vunetlwip_bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
    struct stack_data *sd = vunet_get_private_data();
    struct fd_data *fdd = fduserdata_get(sd->sockets_data,sockfd);
    if (fdd == NULL || fdd->is_netlink == 0)
    {
        if (fdd) fduserdata_put(fdd);
        int (*bind)(int,const struct sockaddr *,socklen_t);
        bind = RESOLVE_SYM(lwip_bind,int (*)(int,const struct sockaddr *,socklen_t),sd);
        return bind(sockfd,addr,addrlen);
    }
    else
    {
        fduserdata_put(fdd);
        return 0;
    }
}

static int vunetlwip_connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
    struct stack_data *sd = vunet_get_private_data();
    int (*connect)(int,const struct sockaddr *,socklen_t);
    connect = RESOLVE_SYM(lwip_connect,int (*)(int,const struct sockaddr *,socklen_t),sd);
    return connect(sockfd,addr,addrlen);
}

static int vunetlwip_listen(int sockfd, int backlog) {
    struct stack_data *sd = vunet_get_private_data();
    int (*listen)(int,int);
    listen = RESOLVE_SYM(lwip_listen,int (*)(int,int),sd);
    return listen(sockfd,backlog);
}

static int vunetlwip_accept4(int sockfd, struct sockaddr *addr, socklen_t *addrlen, int flags) {
    // FIXME The flags are currently ignored
    struct stack_data *sd = vunet_get_private_data();
    int (*accept)(int,struct sockaddr *,socklen_t *);
    accept = RESOLVE_SYM(lwip_accept,int (*)(int,struct sockaddr *,socklen_t *),sd);
    return accept(sockfd,addr,addrlen);
}

static int vunetlwip_getsockname(int sockfd, struct sockaddr *addr, socklen_t *addrlen) {
    struct stack_data *sd = vunet_get_private_data();
    struct fd_data *fdd = fduserdata_get(sd->sockets_data,sockfd);
    if (fdd == NULL || fdd->is_netlink == 0)
    {
        if (fdd) fduserdata_put(fdd);
        int (*getsockname)(int,struct sockaddr *,socklen_t *);
        getsockname = RESOLVE_SYM(lwip_getsockname,int (*)(int,struct sockaddr *,socklen_t *),sd);
        return getsockname(sockfd,addr,addrlen);
    }
    else
    {
        fduserdata_put(fdd);
        struct sockaddr_nl *raddr = (struct sockaddr_nl *) addr;
        raddr->nl_family = AF_NETLINK;
        raddr->nl_pad = 0;
        raddr->nl_pid = 0;
        raddr->nl_groups = 0;
        *addrlen = sizeof(struct sockaddr_nl);
        return 0;
    }
}

static int vunetlwip_getpeername(int sockfd, struct sockaddr *addr, socklen_t *addrlen) {
    struct stack_data *sd = vunet_get_private_data();
    int (*getpeername)(int,struct sockaddr *,socklen_t *);
    getpeername = RESOLVE_SYM(lwip_getpeername,int (*)(int,struct sockaddr *,socklen_t *),sd);
    return getpeername(sockfd,addr,addrlen);
}

static ssize_t vunetlwip_recvfrom(void *buf, size_t len, int flags, struct sockaddr *from, socklen_t
        *fromlen, struct fd_data *fdd)
{
    ssize_t retval = 0;
    ssize_t copylen = 0;
    struct nlq_msg *headmsg = nlq_head(fdd->msgq);
    if (headmsg == NULL) {
        return -ENODATA;
    }
    if (len < headmsg->nlq_size) {
        if (flags & MSG_TRUNC)
            retval = headmsg->nlq_size;
        else
            retval = len;
        copylen = len;
    } else
        retval = copylen = headmsg->nlq_size;
    if (buf != NULL && copylen > 0)
        memcpy(buf, headmsg->nlq_packet, copylen);
    if (!(flags & MSG_PEEK)) {
        nlq_dequeue(&fdd->msgq);
        nlq_freemsg(headmsg);
        if (nlq_length(fdd->msgq) == 0)
            vpoll_ctl(fdd->fd,VPOLL_CTL_DELEVENTS,EPOLLIN);
    }
    if (fromlen && *fromlen >= sizeof(struct sockaddr_nl)) {
        struct sockaddr_nl *socknl = (struct sockaddr_nl *)from;
        socknl->nl_family = AF_NETLINK;
        socknl->nl_pad = 0;
        socknl->nl_pid = 0;
        socknl->nl_groups = 0;
        *fromlen = sizeof(struct sockaddr_nl);
    }
    fduserdata_put(fdd);
    return retval;
}

static ssize_t vunetlwip_recvmsg(int sockfd, struct msghdr *msg, int flags) {
    struct stack_data *sd = vunet_get_private_data();
    struct fd_data *fdd = fduserdata_get(sd->sockets_data,sockfd);
    if (fdd == NULL || fdd->is_netlink == 0)
    {
        if (fdd) fduserdata_put(fdd);
        ssize_t (*recvmsg)(int,struct msghdr *,int);
        recvmsg = RESOLVE_SYM(lwip_recvmsg,ssize_t (*)(int,struct msghdr *,int),sd);
        return recvmsg(sockfd,msg,flags);
    }
    else
    {
        msg->msg_controllen=0;
        if (msg->msg_iovlen == 1) {
            ssize_t ret = vunetlwip_recvfrom(msg->msg_iov->iov_base, msg->msg_iov->iov_len, flags,
                    msg->msg_name, &(msg->msg_namelen), fdd);
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
            size= vunetlwip_recvfrom(lbuf,totalsize,flags, msg->msg_name, &(msg->msg_namelen), fdd);
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
}

void *netif_netlink_searchlink(struct nlmsghdr *msg, struct nlattr **attr, void *handle) {
    struct stack_data *sd = (struct stack_data *) handle;
	struct ifinfomsg *ifi=(struct ifinfomsg *)(msg+1);
    struct netif * (*netif_find)(const char *) = RESOLVE_SYM(netif_find,struct netif * (*)(const char *),sd);
    struct netif * (*netif_get_by_index)(u8_t) = RESOLVE_SYM(netif_get_by_index,struct netif * (*)(u8_t) ,sd);
    void (*lock)(void) = RESOLVE_SYM(sys_lock_tcpip_core,void  (*)(void),sd);
    void (*unlock)(void) = RESOLVE_SYM(sys_unlock_tcpip_core,void  (*)(void),sd);
    void *ret = NULL;
    // To call raw api functions (netif_find and netif_get_by_index) there is the need to acquire
    // the TCPIP core lock
    lock();
    ret = netif_get_by_index(ifi->ifi_index);
    if (!ret && attr[IFLA_IFNAME] != NULL)
        ret = netif_find((char*)(attr[IFLA_IFNAME] + 1));
    unlock();
    return ret;
}

#define netif_get_index(netif)      ((u8_t)((netif)->num + 1))

static void nl_dump1link(struct nlq_msg *msg, struct netif *nip) {
    nlq_addstruct(msg, ifinfomsg, .ifi_family=AF_INET6, .ifi_index=netif_get_index(nip), .ifi_type= nip->link_type,
            .ifi_flags=nip->flags, .ifi_change=0xffffffff); 
    nlq_addattr(msg, IFLA_ADDRESS, nip->hwaddr, nip->hwaddr_len);
    char name[4];
    name[0] = nip->name[0];
    name[1] = nip->name[1];
    name[2] = nip->num % 10 + '0';
    name[3]=0;
    nlq_addattr(msg, IFLA_IFNAME, name, sizeof(name));
    // TODO Could probably abstract all this in a macro, or look for a macro in the lwipv6 code
    char brd_addr[] = "\377\377\377\377\377\377";
    nlq_addattr(msg, IFLA_BROADCAST, brd_addr, 6);
    nlq_addattr(msg, IFLA_MTU, &(nip->mtu), sizeof(nip->mtu));
    int tmp = 0;
    nlq_addattr(msg, IFLA_TXQLEN, &tmp, sizeof(int));
}

int netif_netlink_getlink(void *entry, struct nlmsghdr *msg, struct nlattr **attr, struct nlq_msg
        **reply_msgq, void *handle)
{
    struct stack_data *sd = (struct stack_data *) handle;
	if (entry == NULL) { // DUMP
        struct netif *nip;
        struct netif *netif_list = RESOLVE_SYM(netif_list,struct netif *,sd);
		for (nip = netif_list; nip != NULL ; nip = nip->next) {
			struct nlq_msg *newmsg = nlq_createmsg(RTM_NEWLINK, NLM_F_MULTI, msg->nlmsg_seq, 0);
			nl_dump1link(newmsg, nip);
			nlq_complete_enqueue(newmsg, reply_msgq);
		}
		return 0;
	} else {
		struct nlq_msg *newmsg = nlq_createmsg(RTM_NEWLINK, 0, msg->nlmsg_seq, 0);
		nl_dump1link(newmsg, entry);
		nlq_complete_enqueue(newmsg, reply_msgq);
		return 1;
	}
}

int netif_netlink_setlink(void *entry, struct nlmsghdr *msg, struct nlattr **attr, void *handle){
    // XXX Right now it only supports set up and down as a link modification
    struct stack_data *sd = (struct stack_data *) handle;
	struct ifinfomsg *ifi=(struct ifinfomsg *)(msg+1);
    struct netif *nip = (struct netif *) entry;
    void (*lock)(void) = RESOLVE_SYM(sys_lock_tcpip_core,void  (*)(void),sd);
    void (*unlock)(void) = RESOLVE_SYM(sys_unlock_tcpip_core,void  (*)(void),sd);
    void (*netif_setupdown)(struct netif *);
    if (ifi->ifi_flags & IFF_UP)
        netif_setupdown = RESOLVE_SYM(netif_set_up,void  (*)(struct netif *),sd);
    else
        netif_setupdown = RESOLVE_SYM(netif_set_down,void  (*)(struct netif *),sd);
    lock();
    netif_setupdown(nip);
    unlock();
    return 0;
}

int prefixlen_from_mask(uint32_t mask)
{
    int length = 0;
    int i;
    for (i=0; i < 32; i++)
        if (mask & (1 << (31-i)))
            length++;
        else
            break;
    return length;
}

struct ip_addr_info {
    struct netif *nip;  // Interface having the required address
    int addr_idx;       // Index in the netif IPv6 addresses array; i < 0 then the required address is IPv4
};

int compare_addresses(const ip_addr_t *addr1, uint32_t *addr2, int is_v4)
{
    if (is_v4)
    {
        uint32_t tmp = ntohl(ip_2_ip4(addr1)->addr);
        return memcmp(&tmp, addr2, sizeof(uint32_t)) == 0;
    }
    else
    {
        int i;
        for(i = 0; i < 4; i++)
        {
            // XXX Should I check the zone?
            uint32_t tmp = ntohl(ip_2_ip6(addr1)->addr[i]);
            if (memcmp(&tmp,addr2+i,sizeof(uint32_t)) != 0)
                return 0;
        }
        return 1;
    }
}

// XXX to be debugged
void *netif_netlink_searchaddr(struct nlmsghdr *msg, struct nlattr **attr, void *handle) {
	struct ifaddrmsg *ifa=(struct ifaddrmsg *)(msg+1);
    struct stack_data *sd = (struct stack_data *) handle;
    void (*lock)(void) = RESOLVE_SYM(sys_lock_tcpip_core,void  (*)(void),sd);
    void (*unlock)(void) = RESOLVE_SYM(sys_unlock_tcpip_core,void  (*)(void),sd);
    struct netif * (*netif_get_by_index)(u8_t) = RESOLVE_SYM(netif_get_by_index,struct netif * (*)(u8_t) ,sd);
    lock();
	struct netif *nip = netif_get_by_index(ifa->ifa_index);
    if (nip)
    {
        /* As per man 7 rtnetlink ifa_family can currently be either AF_INET or AF_INET6 */
        if (ifa->ifa_family == AF_INET)
        {
            if (ifa->ifa_prefixlen == prefixlen_from_mask(ntohl((netif_ip4_netmask(nip))->addr)) &&
                    attr[IFA_ADDRESS] != NULL &&
                    compare_addresses(netif_ip_addr4(nip),(uint32_t*)(attr[IFA_ADDRESS]+1),1)
                    )
            {
                struct ip_addr_info *ipi = (struct ip_addr_info *) malloc(sizeof(struct ip_addr_info));
                if (!ipi)
                {
                    unlock();
                    errno = ENOMEM;
                    return NULL;
                }
                else
                {
                    ipi->addr_idx = -1;
                    ipi->nip = nip;
                    unlock();
                    return ipi;
                }
            }
            else
            {
                unlock();
                return NULL;
            }
        }
        else if (ifa->ifa_family == AF_INET6)
        {
            int i;
            for (i = 0; i < LWIP_IPV6_NUM_ADDRESSES; i++)
                if (!ip6_addr_isinvalid(netif_ip6_addr_state(nip, i)) && attr[IFA_ADDRESS] != NULL
                        && compare_addresses(netif_ip_addr6(nip,i),(uint32_t*)(attr[IFA_ADDRESS]+1),0))
                {
                    struct ip_addr_info *ipi = (struct ip_addr_info *) malloc(sizeof(struct ip_addr_info));
                    if (!ipi)
                    {
                        unlock();
                        errno = ENOMEM;
                        return NULL;
                    }
                    else
                    {
                        ipi->addr_idx = i;
                        ipi->nip = nip;
                        unlock();
                        return ipi;
                    }
                }

            unlock();
            return NULL;
        }
        else
        {
            unlock();
            return NULL;
        }
    }
    else
    {
        unlock();
        return NULL;
    }
}

static void nl_dump1addr(struct nlq_msg *msg, const ip_addr_t *ip, uint32_t netmask, int isv4, int index) {
    unsigned char scope = 0;
    unsigned char family = isv4 ? AF_INET : AF_INET6;
    // XXX I can't seem to find a place to set a prefix length for a IPv6 address in lwip, so
    // let's say 64
    unsigned char prefixlen = isv4 ? prefixlen_from_mask(ntohl(netmask)) : 64;

    // TODO scope resolution, flags support (probably absent from lwip)
    /*
    if ((ntohl(ipl->ipaddr.addr[0]) & 0xff000000) == 0xfe000000) {
        if ((ntohl(ipl->ipaddr.addr[0]) & 0xC00000) == 0x800000)
            scope=RT_SCOPE_LINK;
        else if ((ntohl(ipl->ipaddr.addr[0]) & 0xC00000)== 0x08000000)
            scope=RT_SCOPE_SITE;
    } else if ((ntohl(ipl->ipaddr.addr[0]) & 0xff000000) == 0) {
        if (ip_addr_is_v4comp(&(ipl->ipaddr))) {
            if (ntohl(ipl->ipaddr.addr[3]) >> 24 == 0x7f)
                scope=RT_SCOPE_HOST;
        } else
            scope=RT_SCOPE_HOST;
    }
    */

	nlq_addstruct(msg, ifaddrmsg,
			.ifa_family=family,
			.ifa_prefixlen=prefixlen,
            .ifa_index=index,
            .ifa_flags=0,
			.ifa_scope=scope
			);

	if (isv4)
    {
        uint32_t tmp = ntohl(ip_2_ip4(ip)->addr);
        nlq_addattr(msg, IFA_ADDRESS, &tmp, sizeof(uint32_t));
    }
	else
    {
        uint32_t tmp[4];
        int i;
        for (i = 0; i < 4; i++)
            tmp[i] = ntohl((ip_2_ip6(ip))->addr[i]);
        nlq_addattr(msg, IFA_ADDRESS, &tmp, 4*sizeof(uint32_t));
    }
}

int netif_netlink_getaddr(void *entry, struct nlmsghdr *msg, struct nlattr **attr, struct nlq_msg
        **reply_msgq, void *handle){
    struct stack_data *sd = (struct stack_data *) handle;
	struct ifaddrmsg *ifa=(struct ifaddrmsg *)(msg+1);
    struct ip_addr_info *ipi = (struct ip_addr_info *) entry;
    void (*lock)(void) = RESOLVE_SYM(sys_lock_tcpip_core,void  (*)(void),sd);
    void (*unlock)(void) = RESOLVE_SYM(sys_unlock_tcpip_core,void  (*)(void),sd);
    struct netif *netif_list = RESOLVE_SYM(netif_list,struct netif *,sd);
    struct netif * (*netif_get_by_index)(u8_t) = RESOLVE_SYM(netif_get_by_index,struct netif * (*)(u8_t) ,sd);
    lock();
    if (entry == NULL) {
        struct netif *nip = netif_get_by_index(ifa->ifa_index);
		for (nip = netif_list; nip != NULL ; nip = nip->next)
        {
            int idx = netif_get_index(nip);
            struct nlq_msg *newmsg = nlq_createmsg(RTM_NEWADDR, NLM_F_MULTI, msg->nlmsg_seq, 0);
            nl_dump1addr(newmsg, netif_ip_addr4(nip),netif_ip4_netmask(nip)->addr,1,idx);
            nlq_complete_enqueue(newmsg, reply_msgq);
            int i;
            for (i = 0; i < LWIP_IPV6_NUM_ADDRESSES; i++)
            {
                if (!ip6_addr_isinvalid(netif_ip6_addr_state(nip,i)))
                {
                    struct nlq_msg *newmsg = nlq_createmsg(RTM_NEWADDR, NLM_F_MULTI, msg->nlmsg_seq, 0);
                    nl_dump1addr(newmsg, netif_ip_addr6(nip,i),0,0,idx);
                    nlq_complete_enqueue(newmsg, reply_msgq);
                }
            }
        }
        unlock();
        return 0;
    }
    else {
        struct netif *nip = ipi->nip;
        struct nlq_msg *newmsg = nlq_createmsg(RTM_NEWADDR, 0, msg->nlmsg_seq, 0);
        if (ipi->addr_idx < 0)
            nl_dump1addr(newmsg, netif_ip_addr4(nip), netif_ip4_netmask(nip)->addr, 1, netif_get_index(nip));
        else
            nl_dump1addr(newmsg, netif_ip_addr6(nip,ipi->addr_idx), 0, 0, netif_get_index(nip));
        nlq_complete_enqueue(newmsg, reply_msgq);
        free(ipi);
        unlock();
        return 1;
    }
}

void prefix2mask(int len, ip4_addr_t *netmask)
{
    netmask->addr = 0;
    if (len >= 0 && len <= 32)
    {
        int i;
        for(i = 0; i < len; i++)
            netmask->addr |= (1 << (31-i));
    }
    netmask->addr = htonl(netmask->addr);
}

int ip_addr_and_netmask_from_netlink_msg(struct ifaddrmsg *ifa, struct nlattr
        **attr, ip_addr_t *ipaddr, ip_addr_t *netmask){

    int isv4 = ifa->ifa_family == PF_INET;
    if (ipaddr && (attr[IFA_ADDRESS] != NULL || attr[IFA_LOCAL] != NULL )) {
        unsigned short a = (attr[IFA_ADDRESS] != NULL) ? IFA_ADDRESS : IFA_LOCAL;
        if (isv4)
        {
            if (netmask)
                prefix2mask((int)(ifa->ifa_prefixlen),ip_2_ip4(netmask));
            if (attr[a]->nla_len == 8) {
                uint32_t tmp;
                memcpy(&tmp,(int *)(attr[a]+1),sizeof(uint32_t));
                ip_2_ip4(ipaddr)->addr = htonl(tmp);
                return 0;
            }
            else
                return -EINVAL;
        }
        else
        {
            if (attr[a]->nla_len == 20) {
                uint32_t tmp[4];
                int i;
                uint32_t *addr = (uint32_t *)(attr[a]+1);
                for(i = 0; i < 4; i++)
                    tmp[i] = htonl(addr[i]);
                memcpy(ip_2_ip6(ipaddr)->addr,&tmp,4*sizeof(uint32_t));
                return 0;
            }
            else
                return -EINVAL;
        }
    }
    else
        return -EINVAL;
}

int netif_netlink_addaddr(struct nlmsghdr *msg, struct nlattr **attr, void *handle){
    struct stack_data *sd = (struct stack_data *) handle;
	struct ifaddrmsg *ifa=(struct ifaddrmsg *)(msg+1);
	struct netif *nip;
	ip_addr_t ipaddr,netmask;
    void (*lock)(void) = RESOLVE_SYM(sys_lock_tcpip_core,void  (*)(void),sd);
    void (*unlock)(void) = RESOLVE_SYM(sys_unlock_tcpip_core,void  (*)(void),sd);
    struct netif * (*netif_get_by_index)(u8_t) = RESOLVE_SYM(netif_get_by_index,struct netif * (*)(u8_t) ,sd);
    void (*netif_set_addr) (struct netif *, const ip4_addr_t *, const ip4_addr_t *, const ip4_addr_t
            *) = RESOLVE_SYM(netif_set_addr,void (*)(struct netif *, const ip4_addr_t *, const ip4_addr_t *,
                const ip4_addr_t *),sd);
    err_t (*netif_add_ip6_address)(struct netif *, const ip6_addr_t *, s8_t *) =
        RESOLVE_SYM(netif_add_ip6_address,err_t (*)(struct netif *, const ip6_addr_t *, s8_t *),sd);
    lock();

	nip=netif_get_by_index(ifa->ifa_index);
	if (nip == NULL) {
        unlock();
		fprintf(stderr,"Netlink add index error\n");
		return -ENODEV;
	}

    int n;
    n = ip_addr_and_netmask_from_netlink_msg(ifa,attr,&ipaddr,&netmask);
    if (n < 0)
        return n;

    if (ifa->ifa_family == AF_INET)
        netif_set_addr(nip,ip_2_ip4(&ipaddr),ip_2_ip4(&netmask),NULL);
    else
        netif_add_ip6_address(nip,ip_2_ip6(&ipaddr),NULL);

    unlock();
    return 0;
}

int netif_netlink_deladdr(void *entry, struct nlmsghdr *msg, struct nlattr **attr, void *handle){
    struct stack_data *sd = (struct stack_data *) handle;
    struct ip_addr_info *ipi = (struct ip_addr_info *) entry;
    void (*lock)(void) = RESOLVE_SYM(sys_lock_tcpip_core,void  (*)(void),sd);
    void (*unlock)(void) = RESOLVE_SYM(sys_unlock_tcpip_core,void  (*)(void),sd);
    void (*netif_set_addr) (struct netif *, const ip4_addr_t *, const ip4_addr_t *, const ip4_addr_t
            *) = RESOLVE_SYM(netif_set_addr,void (*)(struct netif *, const ip4_addr_t *, const ip4_addr_t *,
                const ip4_addr_t *),sd);
    void (*netif_ip6_addr_set_state)(struct netif*, s8_t, u8_t) =
        RESOLVE_SYM(netif_ip6_addr_set_state,void (*)(struct netif*, s8_t, u8_t),sd);
    lock();

    if (ipi->addr_idx < 0)
        netif_set_addr(ipi->nip,NULL,NULL,NULL);
    else
        netif_ip6_addr_set_state(ipi->nip, ipi->addr_idx, IP6_ADDR_INVALID);
    unlock();
    return 0;
}

nlq_request_handlers_table handlers_table = {
    [RTMF_LINK]={netif_netlink_searchlink, netif_netlink_getlink, NULL/*netif_netlink_addlink*/,
        NULL /*netif_netlink_dellink*/,  netif_netlink_setlink},
    [RTMF_ADDR]={netif_netlink_searchaddr, netif_netlink_getaddr, netif_netlink_addaddr,
        netif_netlink_deladdr, NULL}
    /*
    [RTMF_ROUTE]={ip_route_netlink_searchroute, ip_route_netlink_getroute,
        ip_route_netlink_addroute, ip_route_netlink_delroute, NULL}
    */
};

static ssize_t vunetlwip_sendto(const void *buf, size_t len, struct fd_data *fdd)
{
    struct nlmsghdr *msg = (struct nlmsghdr *)buf;
    struct stack_data *sd = vunet_get_private_data();

    while (NLMSG_OK(msg, len)) {
        struct nlq_msg *msgq;
        msgq = nlq_process_rtrequest(msg, handlers_table, sd);
        while (msgq != NULL) {
            struct nlq_msg *msg = nlq_dequeue(&msgq);
            //msg->nlq_packet->nlmsg_pid = nl->pid;
            nlq_enqueue(msg, &fdd->msgq);
        }
        msg = NLMSG_NEXT(msg, len);
    }

    if (nlq_length(fdd->msgq) > 0)
        vpoll_ctl(fdd->fd,VPOLL_CTL_ADDEVENTS, EPOLLIN);
    fduserdata_put(fdd);
    return len;
}

static ssize_t vunetlwip_sendmsg(int sockfd, const struct msghdr *msg, int flags) {
    struct stack_data *sd = vunet_get_private_data();
    struct fd_data *fdd = fduserdata_get(sd->sockets_data,sockfd);
    if (fdd == NULL || fdd->is_netlink == 0)
    {
        if (fdd) fduserdata_put(fdd);
        ssize_t (*sendmsg)(int,const struct msghdr *,int);
        sendmsg = RESOLVE_SYM(lwip_sendmsg,ssize_t (*)(int,const struct msghdr *,int),sd);
        return sendmsg(sockfd,msg,flags);
    }
    else
    {
        //msg->msg_controllen=0;
        if (msg->msg_iovlen == 1) {
            return vunetlwip_sendto(msg->msg_iov->iov_base,msg->msg_iov->iov_len,fdd);
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
            size=vunetlwip_sendto(lbuf, totalsize, fdd);
            return size;
        }
    }
}

static int vunetlwip_setsockopt(int sockfd, int level, int optname, const void *optval, socklen_t optlen) {
    // XXX There is a hook that can be defined to support options not provided by lwip. May be
    // useful
    struct stack_data *sd = vunet_get_private_data();
    int (*setsockopt)(int, int,int,const void *,socklen_t);
    setsockopt = RESOLVE_SYM(lwip_setsockopt,int (*)(int, int,int,const void *,socklen_t),sd);
    return setsockopt(sockfd,level,optname,optval,optlen);
}

static int vunetlwip_getsockopt(int sockfd, int level, int optname, void *optval, socklen_t *optlen) {
    // XXX There is a hook that can be defined to support options not provided by lwip. May be
    // useful
    struct stack_data *sd = vunet_get_private_data();
    int (*getsockopt)(int, int,int,void *,socklen_t *);
    getsockopt = RESOLVE_SYM(lwip_getsockopt,int(*)(int, int,int,void *,socklen_t *),sd);
    return getsockopt(sockfd,level,optname,optval,optlen);
}

static int vunetlwip_shutdown(int sockfd, int how) {
    struct stack_data *sd = vunet_get_private_data();
    int (*shutdown)(int,int);
    shutdown = RESOLVE_SYM(lwip_shutdown,int (*)(int, int),sd);
    return shutdown(sockfd,how);
}

static int vunetlwip_ioctl(int s, unsigned long cmd, void *argp) {
    if (s < 0)
        return vunet_is_netdev_ioctl(cmd) ? vunet_ioctl_parms(cmd) : -1;
    else
    {
        struct stack_data *sd = vunet_get_private_data();
        switch (cmd)
        {
            case FIONREAD:
            case FIONBIO:
                {
                    int (*ioctl)(int, long, void *);
                    ioctl = RESOLVE_SYM(lwip_ioctl,int (*)(int, long, void *),sd);
                    return ioctl(s,cmd,argp);
                }
            /* XXX I should make probably make a separate case for SIOCGIFCONF, as in the
             * vuos_example of libnlq */
            default:
                return nlq_server_ioctl(handlers_table, sd, cmd, argp);
        }
    }
}

#if DEBUG
int (*_close)(int);
#endif

static int vunetlwip_close(int fd) {
#if DEBUG
    return _close(fd);
#else
    struct stack_data *sd = vunet_get_private_data();
    struct fd_data *fdd = fduserdata_get(sd->sockets_data,fd);
    if (fdd) fduserdata_del(fdd);
    int (*close)(int);
    close = RESOLVE_SYM(lwip_close,int (*)(int),sd);
    return close(fd);
#endif
}

static int vunetlwip_fcntl(int s, int cmd, long val) {
    struct stack_data *sd = vunet_get_private_data();
    int (*fcntl)(int,int,long);
    fcntl = RESOLVE_SYM(lwip_fcntl,int (*)(int,int,long),sd);
    return fcntl(s,cmd,val);
}

static int vunetlwip_epoll_ctl(int epfd, int op, int fd, struct epoll_event *event) {
    // TODO
    /* Roadmap:
     *  - add the hooks in lwip that notifies about events on the socket
     *  - define the fduserdata table that maps lwip socket fds to vpoll eventfds and respective
     *  epoll_data
     *  - implement the epoll_ctl, this way:
     *    - use the given epfd and add/del/mod the efd corresponding to the given fd
     *    - save the event and data in the fduserdata table
     *  - What does the user defined hook do? It looks up the socket fd in the table, checks the
     *  signaled event and the saved events for that fd. Based on that, it calls vpoll to signal of
     *  the efd the right event to the vuos core
    */
    struct stack_data *sd = vunet_get_private_data();
    struct fd_data *fdd;
    if ((fdd = fduserdata_get(sd->sockets_data,fd)) == NULL)
        return -1;
    else
    {
        fdd->ev.events = event->events;
        //fd->ev->data = event->data;
        epoll_ctl(epfd,op,fdd->fd,event);
        fduserdata_put(fdd);
        return 0;
    }
}

static int vunetlwip_supported_domain(int domain)
{
	switch(domain) {
		case AF_INET:
		case PF_INET6:
		case PF_NETLINK:
		//case PF_PACKET:
			return 1;
		default:
			return 0;
	}
}

static int vunetlwip_supported_ioctl(unsigned long request)
{
    // TODO
    return 0;
}

#if 0
static char *intname[]={"vd","tn","tp"};
#define INTTYPES (sizeof(intname)/sizeof(char *))
static char *paramname[]={"ra"};
#define PARAMTYPES (sizeof(paramname)/sizeof(char *))

struct ifname {
	unsigned char type;
	unsigned char num;
	char *name;
	struct ifname *next;
};

static void iffree(struct ifname *head)
{
	if (head==NULL)
		return;
	else {
		iffree(head->next);
		free(head->name);
		free(head);
	}
}

static char *ifname(struct ifname *head,unsigned char type,unsigned char num)
{
	if (head==NULL)
		return NULL;
	else if (head->type == type && head->num == num)
		return head->name;
	else return ifname(head->next,type,num);
}

static void ifaddname(struct ifname **head,char type,char num,char *name)
{
	struct ifname *thisif=malloc(sizeof (struct ifname));
	if (thisif != NULL) {
		thisif->type=type;
		thisif->num=num;
		thisif->name=strdup(name);
		thisif->next=*head;
		*head=thisif;
	}
}

static void myputenv(struct ifname **head, int *intnum, char *paramval[], char *arg)
{
	int i;
    /* For each interface type */
	for (i=0;i<INTTYPES;i++) {
        /* If a supported interface + a digit has been supplied */
		if (strncmp(arg,intname[i],2)==0 && arg[2] >= '0' && arg[2] <= '9') {
            /* If a named interface has been supplied */
			if (arg[3] == '=') {
                /* Add the given interface to head */
				ifaddname(head, i,arg[2]-'0',arg+4);
				if (arg[2]-'0'+1 > intnum[i]) intnum[i]=arg[2]-'0'+1;
			}
            /* Else just change the number of the supplied interface type, if needed */
			else if (arg[3] == 0) {
				if (arg[2]-'0' > intnum[i]) intnum[i]=arg[2]-'0';
			}
			break;
		}
	}

    /* If a parameter has been supplied, set paramval[i] pointer to the value of the given parameter
     * */
	for (i=0;i<PARAMTYPES;i++) {
		if (strncmp(arg,paramname[i],2)==0) {
			if (arg[2] == '=') {
				paramval[i]=arg+3;
			}
		}
	}
}

static char stdargs[]="vd1";
static void lwipargtoenv(struct stack *s,char *initargs)
{
	char *next;
	char *unquoted;
	char quoted=0;
	char totint=0;
	register int i,j;
	struct ifname *ifh=NULL;
	int intnum[INTTYPES];
	char *paramval[PARAMTYPES];

	memset(intnum,0,sizeof(intnum));
	memset(paramval,0,sizeof(paramval));

	if (initargs==0 || *initargs == 0) initargs=stdargs;
	if (strcmp(initargs,"lo") != 0) {
        /* Until we reach the end of the initargs string */
		while (*initargs != 0) {
            /* Position next and unquoted at the position pointed by initargs of the input string */
			next=initargs;
			unquoted=initargs;
            /* Up until we reach a comma or a quoting sign, as long as we have not reached the end */
            while ((*next != ',' || quoted) && *next != 0) {
                /* Save the character pointed by next in the unquoted string at the position pointed
                 * by unquoted */
                *unquoted=*next;
                /* If we reached the second quoting, turn off the quote flag */
                if (*next == quoted)
                    quoted=0;
                /* If we reach the first quoting, turn on the quote flag, setting it to the quote
                 * sign */
                else if (*next == '\'' || *next == '\"')
                    quoted=*next;
                else
                /* Proceed on the unquoted string*/
                    unquoted++;
                /* Proceed on the initargs string */
                next++;
            }
			if (*next == ',') {
				*unquoted=*next=0;
				next++;
			}
            /* At this point , we have found a string between two commas, which may be quoted, and
             * we have set the comma character with a NULL byte. We have also set next to the next
             * character, to resume later on.  Standard C programs will see the initargs string as a
             * shorter string than the input string, with only the first parameter */
			if (*initargs != 0)
				myputenv(&ifh,intnum,paramval,initargs);
            /*
             * If we have not finished the input string, we put the found parameter in the env with
             * myputenv, and then we start all over again from next
             * */
			initargs=next;
		}
		/* load interfaces */
        /* count the interfaces */
		for (i=0;i<INTTYPES;i++)
			totint+=intnum[i];
        /* at least one */
		if (totint==0)
			intnum[0]=1;
        /* For each type of interface, try to add it to the stack */
		for (j=0;j<intnum[0];j++) {
			if (lwip_vdeif_add(s,ifname(ifh,0,j)) == NULL) 
				fprintf(stderr,"vunetlwip: vd[%d] configuration error\n",j);
		}
		for (j=0;j<intnum[1];j++) {
			if (lwip_tunif_add(s,ifname(ifh,1,j)) == NULL)
				fprintf(stderr,"vunetlwip: tn[%d] configuration error\n",j);
		}
		for (j=0;j<intnum[2];j++) {
			if (lwip_tapif_add(s,ifname(ifh,2,j)) == NULL)
				fprintf(stderr,"vunetlwip: tp[%d] configuration error\n",j);
		}
		iffree(ifh);

		if (paramval[0] != NULL)
			lwip_radv_load_configfile(s,paramval[0]);
	}
}
#endif

static void init_func(void *arg){
    struct stack_data *sd = (struct stack_data *) arg;
    // Stack initialization
    err_t (*tapif_init)(struct netif *);
    struct netif *(*netif_add)(struct netif *netif, const ip4_addr_t *ipaddr, const ip4_addr_t
            *netmask, const ip4_addr_t *gw, void *state, netif_init_fn init, netif_input_fn input);
    int8_t (*tcpipinput)(struct pbuf *p, struct netif *inp);
    // XXX Right now only a tap interface is initialized
    tapif_init = RESOLVE_SYM(tapif_init,err_t (*)(struct netif *),sd);
    netif_add = RESOLVE_SYM(netif_add,struct netif *(*)(struct netif *, const ip4_addr_t *, const
                ip4_addr_t *, const ip4_addr_t *, void *, netif_init_fn , netif_input_fn ),sd);
    tcpipinput = RESOLVE_SYM(tcpip_input,int8_t (*)(struct pbuf *p, struct netif *inp),sd);
    netif_add(sd->netif,NULL,NULL,NULL,NULL,tapif_init,tcpipinput);
}

static int vunetlwip_init(const char *source, unsigned long flags, const char *args, void **private_data) {
    void *handle;
    if ((handle = dlmopen(LM_ID_NEWLM,LIB_LWIP,RTLD_LAZY)) == NULL)
        DL_ERROR(-1);
    else
    {
        unsigned i;
        struct stack_data *sd = malloc(sizeof(struct stack_data));
        if (!sd) goto mem_error;
        sd->sockets_data = fduserdata_create(EFD_TBL_SIZE);
        if (sd->sockets_data == NULL) goto mem_error;
        sd->handle = handle;
        sd->netif = malloc(sizeof(struct netif));
        if (!sd->netif) goto mem_error;
        for(i = 0; i < SYM_NUM; i++)
        {
            sd->lwipsymtab[i] = dlsym(handle,lwip_sym_names[i]);
            if(sd->lwipsymtab[i] == NULL)
            {
                DL_ERROR(-1);
                free(sd);
                dlclose(handle);
            }
        }
#if DEBUG
        _close = RESOLVE_SYM(lwip_close,int (*)(int),sd);
#endif
        (RESOLVE_SYM(tcpip_init,void (*)(tcpip_init_done_fn, void *),sd))(init_func,sd);
        *private_data = sd;
        return 0;
mem_error:
        if (sd) free(sd);
        dlclose(handle);
        errno = ENOMEM;
        return -1;
    }
}

int update_socket_events(int fd, int pollin, int pollout, int pollerr, int *err)
{
    // XXX as of this moment, using the emulation layer of vpoll, pollerr events can't really be
    // signaled
    struct stack_data *sd = vunet_get_private_data();
    struct fd_data *fdd = fduserdata_get(sd->sockets_data,fd);
    if (fdd)
    {
        uint32_t events = 0;
        if (pollin && (fdd->ev.events && EPOLLIN))
            events |= EPOLLIN;
        if (pollout && (fdd->ev.events && EPOLLOUT))
            events |= EPOLLOUT;
        if (pollerr && (fdd->ev.events && EPOLLERR))
            events |= EPOLLERR;
        vpoll_ctl(fdd->fd,VPOLL_CTL_SETEVENTS,events);
        fduserdata_put(fdd);
        return 0;
    }
    else
    {*err = EINVAL; return -1;}
}

static int vunetlwip_fini(void *private_data){
    struct stack_data *sd = private_data;
    void (*lock)(void) = RESOLVE_SYM(sys_lock_tcpip_core,void  (*)(void),sd);
    void (*unlock)(void) = RESOLVE_SYM(sys_unlock_tcpip_core,void  (*)(void),sd);
    void (*netif_remove)(struct netif *) = RESOLVE_SYM(netif_remove,void (*)(struct netif *),sd);
    struct netif *netif_list = RESOLVE_SYM(netif_list,struct netif *,sd);
    struct netif *nip;
    struct fd_data *fdd;
    lock();
    int i;
    /* Closing the active sockets */
    for (i = 0; i < NUM_SOCKETS; i++)
        if ((fdd = fduserdata_get(sd->sockets_data,i)) != NULL)
        {
            fduserdata_put(fdd);
            vunetlwip_close(i);
        }
    /* Removing the interfaces */
    for (nip = netif_list; nip != NULL ; nip = nip->next)
        netif_remove(nip);
    unlock();
    dlclose(sd->handle);
    fduserdata_destroy(sd->sockets_data);
    free(sd->netif);
    free(sd);
	return 0;
}

struct vunet_operations vunet_ops = {
	.socket = vunetlwip_socket,
	.bind = vunetlwip_bind,
	.connect = vunetlwip_connect,
	.listen = vunetlwip_listen,
	.accept4 = vunetlwip_accept4, 
	.getsockname = vunetlwip_getsockname,
	.getpeername = vunetlwip_getpeername,
	.recvmsg = vunetlwip_recvmsg,
	.sendmsg = vunetlwip_sendmsg,
	.setsockopt = vunetlwip_setsockopt,
	.getsockopt = vunetlwip_getsockopt,
	.shutdown = vunetlwip_shutdown,
    .ioctl = vunetlwip_ioctl,
	.close = vunetlwip_close,
	.fcntl = vunetlwip_fcntl,
    .epoll_ctl = vunetlwip_epoll_ctl,
	.supported_domain = vunetlwip_supported_domain,
	.supported_ioctl = vunetlwip_supported_ioctl,
	.init = vunetlwip_init,
	.fini = vunetlwip_fini
};
