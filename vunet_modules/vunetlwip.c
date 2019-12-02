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
#include <socket_event.h>
#include <vunet.h>
#include <fduserdata.h>
#include <vpoll.h>
#include <libnlq.h>
#include <linux/netlink.h>
#include <sys/un.h>
#include <signal.h>

#define NUM_SOCKETS MEMP_NUM_NETCONN
#define LIB_LWIP "liblwip.so"

/* The HELPER_MACRO is defined, undefined and redefined to assume different meanings in the
 * definition of the symbol list for the shared object lwip.so. This way we can create different
 * lists, where each list is the result of the application of HELPER_MACRO to each of the symbol
 * listed here. For example, this way the list of strings for the symbols is generated, and
 * similarly the list of numerical indices for each symbol is generated.
 *
 * To add a new symbol from the shared object all that is needed is to add a line at the end of this
 * list, similar to the previous.
 * */
#define VUNETLWIP_SYMBOL_LIST \
    HELPER_MACRO(lwip_socket), \
    HELPER_MACRO(lwip_bind), \
    HELPER_MACRO(lwip_connect), \
    HELPER_MACRO(lwip_listen), \
    HELPER_MACRO(lwip_accept), \
    HELPER_MACRO(lwip_getsockname), \
    HELPER_MACRO(lwip_getpeername), \
    HELPER_MACRO(lwip_recvmsg), \
    HELPER_MACRO(lwip_sendmsg), \
    HELPER_MACRO(lwip_setsockopt), \
    HELPER_MACRO(lwip_getsockopt), \
    HELPER_MACRO(lwip_shutdown), \
    HELPER_MACRO(lwip_ioctl), \
    HELPER_MACRO(lwip_fcntl), \
    HELPER_MACRO(lwip_close), \
    HELPER_MACRO(netif_find), \
    HELPER_MACRO(netif_get_by_index), \
    HELPER_MACRO(sys_lock_tcpip_core), \
    HELPER_MACRO(sys_unlock_tcpip_core), \
    HELPER_MACRO(netif_list), \
    HELPER_MACRO(netif_set_up), \
    HELPER_MACRO(netif_set_down), \
    HELPER_MACRO(netif_set_addr), \
    HELPER_MACRO(tapif_init), \
    HELPER_MACRO(netif_add), \
    HELPER_MACRO(tcpip_input), \
    HELPER_MACRO(tcpip_init), \
    HELPER_MACRO(netif_remove), \
    HELPER_MACRO(netif_ip6_addr_set_state), \
    HELPER_MACRO(netif_add_ip6_address), \
    HELPER_MACRO(register_socket_event_callback)

#define HELPER_MACRO(X) #X
const char* lwip_sym_names[] = { VUNETLWIP_SYMBOL_LIST };
#undef HELPER_MACRO

#define HELPER_MACRO(X) X ## _IDX
enum { VUNETLWIP_SYMBOL_LIST, SYM_NUM };
#undef HELPER_MACRO

/* In this macro x is purposedly written without parentheses around it to permit a return statement
   with nothing as an argument (e.g. in void functions). Use carefully
   */
#define DL_ERROR(x) do {\
    fprintf(stderr,"vunetlwip.c, line:%d, %s\n",__LINE__,dlerror());\
    return x;\
} while(0)

#define EFD_TBL_SIZE 64

#define RESOLVE_SYM(var,s,sd) (var = (typeof(var)) ((sd)->lwipsymtab[s##_IDX]))

struct stack_data {
    void *handle;               // Handle to lwip.so symbols
    struct netif *netif;        // Network interface
    void * lwipsymtab[SYM_NUM]; // Lwip symbol table, to retrieve stack functions and variables
    FDUSERDATA *sockets_data;   // Used for event handling and Netlink sockets
};

struct fd_data {
    struct epoll_event ev;      // Events virtualized processes are waiting on
    int fd;                     // Eventfd used to signal events with vpoll
    unsigned char is_netlink;   // A flag indicating if this is a Netlink socket
    struct nlq_msg *msgq;       // Queue of Netlink messages for stack configuration
};

static int vunetlwip_socket(int domain, int type, int protocol){
    struct stack_data *sd = vunet_get_private_data();
    int fd;
    int is_netlink = 0;
    int (*socket)(int,int,int);
    RESOLVE_SYM(socket,lwip_socket,sd);
    if (domain != AF_NETLINK)
    {
        /* lwip assumes that every SOCK_DGRAM socket is a UDP socket. Thus, when DGRAM is used to
         * open a ICMP socket lwip actually opens a UDP one, and sends UDP packet, with unwanted
         * results. Here we change the type to SOCK_RAW. The best thing would be to support this
         * case directly in lwip */
        if (type == SOCK_DGRAM && protocol == IPPROTO_ICMP)
            type = SOCK_RAW;
        fd = socket(domain,type,protocol);
    }
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
        fdd->fd = vpoll_create(EPOLLOUT,0); /* The socket is ready for packet sending */
        fdd->is_netlink = is_netlink;
        fdd->msgq = NULL;
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
        RESOLVE_SYM(bind,lwip_bind,sd);
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
    RESOLVE_SYM(connect,lwip_connect,sd);
    return connect(sockfd,addr,addrlen);
}

static int vunetlwip_listen(int sockfd, int backlog) {
    struct stack_data *sd = vunet_get_private_data();
    int (*listen)(int,int);
    RESOLVE_SYM(listen,lwip_listen,sd);
    return listen(sockfd,backlog);
}

static int vunetlwip_accept4(int sockfd, struct sockaddr *addr, socklen_t *addrlen, int flags) {
    // FIXME The flags are currently ignored
    struct stack_data *sd = vunet_get_private_data();
    int (*accept)(int,struct sockaddr *,socklen_t *);
    RESOLVE_SYM(accept,lwip_accept,sd);
    return accept(sockfd,addr,addrlen);
}

static int vunetlwip_getsockname(int sockfd, struct sockaddr *addr, socklen_t *addrlen) {
    struct stack_data *sd = vunet_get_private_data();
    struct fd_data *fdd = fduserdata_get(sd->sockets_data,sockfd);
    if (fdd == NULL || fdd->is_netlink == 0)
    {
        if (fdd) fduserdata_put(fdd);
        int (*getsockname)(int,struct sockaddr *,socklen_t *);
        RESOLVE_SYM(getsockname,lwip_getsockname,sd);
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
    RESOLVE_SYM(getpeername,lwip_getpeername,sd);
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
        RESOLVE_SYM(recvmsg,lwip_recvmsg,sd);
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
    struct netif * (*netif_find)(const char *);
    RESOLVE_SYM(netif_find,netif_find,sd);
    struct netif * (*netif_get_by_index)(u8_t);
    RESOLVE_SYM(netif_get_by_index,netif_get_by_index,sd);
    void (*lock)(void);
    RESOLVE_SYM(lock,sys_lock_tcpip_core,sd);
    void (*unlock)(void);
    RESOLVE_SYM(unlock,sys_unlock_tcpip_core,sd);
    void *ret = NULL;
    // In order to call raw api functions (netif_find and netif_get_by_index) we need to acquire the
    // TCPIP core lock
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
        struct netif *netif_list;
        RESOLVE_SYM(netif_list,netif_list,sd);
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
    void (*lock)(void);
    RESOLVE_SYM(lock,sys_lock_tcpip_core,sd);
    void (*unlock)(void);
    RESOLVE_SYM(unlock,sys_unlock_tcpip_core,sd);
    void (*netif_setupdown)(struct netif *);
    if (ifi->ifi_flags & IFF_UP)
        RESOLVE_SYM(netif_setupdown,netif_set_up,sd);
    else
        RESOLVE_SYM(netif_setupdown,netif_set_down,sd);
    lock();
    netif_setupdown(nip);
    unlock();
    return 0;
}

int netif_netlink_addlink(struct nlmsghdr *msg, struct nlattr **attr, void *stackinfo) {
    struct stack_data *sd = (struct stack_data *) handle;
    struct ifinfomsg *ifi=(struct ifinfomsg *)(msg+1);
    struct netif *(*netif_add)(struct netif *netif, const ip4_addr_t *ipaddr, const ip4_addr_t
            *netmask, const ip4_addr_t *gw, void *state, netif_init_fn init, netif_input_fn input);
    int8_t (*tcpipinput)(struct pbuf *p, struct netif *inp);
    int8_t (*tcpipinput)(struct pbuf *p, struct netif *inp);
    void (*lock)(void);
    void (*unlock)(void);
    void (*netif_setupdown)(struct netif *);

    RESOLVE_SYM(netif_add,netif_add,sd);
    RESOLVE_SYM(tcpipinput,tcpip_input,sd);
    RESOLVE_SYM(lock,sys_lock_tcpip_core,sd);
    RESOLVE_SYM(unlock,sys_unlock_tcpip_core,sd);

    if (attr[IFLA_INFO_KIND]) {
        struct netif *nif;
        netif_init_fn init_func;
        void *state;

        switch(strcase(attr[IFLA_INFO_KIND]+1))
        {
            case STRCASE(v,d,e):
                init_func = vde_init;
                state = attr[IFLA_INFO_DATA] + 1;
                break;
            case STRCASE(t,a,p):
                //TODO
                break;
            default:
                return -EINVAL;
                break;
        }

        nif = (struct netif *) malloc(sizeof(struct netif));
        if (!nip) {
            return -ENOMEM;
        }
        else {
            lock();
            void *ret = netif_add(nif, NULL, NULL, NULL, state, init_func, tcpipinput);
            if (!ret) {
                free(nif);
                unlock();
                return -EINVAL;
            }
            else
            {
                // Adding the new nif to the netifs of the stack
                ret->next = sd->netif;
                sd->netif = ret->next;
                unlock();
                return 0;
            }
        }
    }
    else {
        return -EINVAL;
    }
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
    int addr_idx;       // Index in the netif IPv6 addresses array; if < 0 then the required address is IPv4
};

int compare_addresses(const ip_addr_t *addr1, uint32_t *addr2, int is_v4)
{
    if (is_v4)
        return memcmp(&(ip_2_ip4(addr1)->addr), addr2, sizeof(uint32_t)) == 0;
    else
    {
        int i;
        for(i = 0; i < 4; i++)
            if (memcmp(ip_2_ip6(addr1)->addr+i,addr2+i,sizeof(uint32_t)) != 0)
                return 0;
        return 1;
    }
}

void *netif_netlink_searchaddr(struct nlmsghdr *msg, struct nlattr **attr, void *handle) {
    struct ifaddrmsg *ifa=(struct ifaddrmsg *)(msg+1);
    struct stack_data *sd = (struct stack_data *) handle;
    void (*lock)(void);
    RESOLVE_SYM(lock,sys_lock_tcpip_core,sd);
    void (*unlock)(void);
    RESOLVE_SYM(unlock,sys_unlock_tcpip_core,sd);
    struct netif * (*netif_get_by_index)(u8_t);
    RESOLVE_SYM(netif_get_by_index,netif_get_by_index,sd);
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
        nlq_addattr(msg, IFA_ADDRESS, &(ip_2_ip4(ip)->addr), sizeof(uint32_t));
    else
        nlq_addattr(msg, IFA_ADDRESS, (ip_2_ip6(ip))->addr, 4*sizeof(uint32_t));
}

int netif_netlink_getaddr(void *entry, struct nlmsghdr *msg, struct nlattr **attr, struct nlq_msg
        **reply_msgq, void *handle){
    struct stack_data *sd = (struct stack_data *) handle;
    struct ifaddrmsg *ifa=(struct ifaddrmsg *)(msg+1);
    struct ip_addr_info *ipi = (struct ip_addr_info *) entry;
    void (*lock)(void);
    RESOLVE_SYM(lock,sys_lock_tcpip_core,sd);
    void (*unlock)(void);
    RESOLVE_SYM(unlock,sys_unlock_tcpip_core,sd);
    struct netif *netif_list;
    RESOLVE_SYM(netif_list,netif_list,sd);
    struct netif * (*netif_get_by_index)(u8_t);
    RESOLVE_SYM(netif_get_by_index,netif_get_by_index,sd);
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
                memcpy(&ip_2_ip4(ipaddr)->addr,(int *)(attr[a]+1),sizeof(uint32_t));
                return 0;
            }
            else
                return -EINVAL;
        }
        else
        {
            if (attr[a]->nla_len == 20) {
                memcpy(ip_2_ip6(ipaddr)->addr,(uint32_t *)(attr[a]+1),4*sizeof(uint32_t));
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
    void (*lock)(void);
    RESOLVE_SYM(lock,sys_lock_tcpip_core,sd);
    void (*unlock)(void);
    RESOLVE_SYM(unlock,sys_unlock_tcpip_core,sd);
    struct netif * (*netif_get_by_index)(u8_t);
    RESOLVE_SYM(netif_get_by_index,netif_get_by_index,sd);
    void (*netif_set_addr) (struct netif *, const ip4_addr_t *, const ip4_addr_t *, const ip4_addr_t *);
    RESOLVE_SYM(netif_set_addr,netif_set_addr,sd);
    err_t (*netif_add_ip6_address)(struct netif *, const ip6_addr_t *, s8_t *);
    RESOLVE_SYM(netif_add_ip6_address,netif_add_ip6_address,sd);
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
    void (*lock)(void);
    RESOLVE_SYM(lock,sys_lock_tcpip_core,sd);
    void (*unlock)(void);
    RESOLVE_SYM(unlock,sys_unlock_tcpip_core,sd);
    void (*netif_set_addr) (struct netif *, const ip4_addr_t *, const ip4_addr_t *, const ip4_addr_t *);
    RESOLVE_SYM(netif_set_addr,netif_set_addr,sd);
    void (*netif_ip6_addr_set_state)(struct netif*, s8_t, u8_t);
    RESOLVE_SYM(netif_ip6_addr_set_state,netif_ip6_addr_set_state,sd); lock();

    if (ipi->addr_idx < 0)
        netif_set_addr(ipi->nip,NULL,NULL,NULL);
    else
        netif_ip6_addr_set_state(ipi->nip, ipi->addr_idx, IP6_ADDR_INVALID);
    unlock();
    return 0;
}

nlq_request_handlers_table handlers_table = {
    [RTMF_LINK]={netif_netlink_searchlink, netif_netlink_getlink, netif_netlink_addlink,
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
    if (fdd == NULL || !fdd->is_netlink)
    {
        if (fdd) fduserdata_put(fdd);
        ssize_t (*sendmsg)(int,const struct msghdr *,int);
        RESOLVE_SYM(sendmsg,lwip_sendmsg,sd);
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
    RESOLVE_SYM(setsockopt,lwip_setsockopt,sd);
    return setsockopt(sockfd,level,optname,optval,optlen);
}

static int vunetlwip_getsockopt(int sockfd, int level, int optname, void *optval, socklen_t *optlen) {
    // XXX There is a hook that can be defined to support options not provided by lwip. May be
    // useful
    struct stack_data *sd = vunet_get_private_data();
    int (*getsockopt)(int, int,int,void *,socklen_t *);
    RESOLVE_SYM(getsockopt,lwip_getsockopt,sd);
    return getsockopt(sockfd,level,optname,optval,optlen);
}

static int vunetlwip_shutdown(int sockfd, int how) {
    struct stack_data *sd = vunet_get_private_data();
    int (*shutdown)(int,int);
    RESOLVE_SYM(shutdown,lwip_shutdown,sd);
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
                    RESOLVE_SYM(ioctl,lwip_ioctl,sd);
                    return ioctl(s,cmd,argp);
                }
                /* XXX I should probably make a separate case for SIOCGIFCONF, as in the vuos_example of
                 * libnlq */
            default:
                return nlq_server_ioctl(handlers_table, sd, cmd, argp);
        }
    }
}

static int vunetlwip_close(int fd) {
    struct stack_data *sd = vunet_get_private_data();
    struct fd_data *fdd = fduserdata_get(sd->sockets_data,fd);
    if (fdd) fduserdata_del(fdd);
    int (*close)(int);
    RESOLVE_SYM(close,lwip_close,sd);
    return close(fd);
}

static int vunetlwip_fcntl(int s, int cmd, long val) {
    struct stack_data *sd = vunet_get_private_data();
    int (*fcntl)(int,int,long);
    RESOLVE_SYM(fcntl,lwip_fcntl,sd);
    return fcntl(s,cmd,val);
}

static int vunetlwip_epoll_ctl(int epfd, int op, int fd, struct epoll_event *event) {
    struct stack_data *sd = vunet_get_private_data();
    struct fd_data *fdd;
    if ((fdd = fduserdata_get(sd->sockets_data,fd)) == NULL)
        return -1;
    else
    {
        fdd->ev.events = event ? event->events : 0;
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

static void init_func(void *arg){
    struct stack_data *sd = (struct stack_data *) arg;
    // Stack initialization
    err_t (*tapif_init)(struct netif *);
    struct netif *(*netif_add)(struct netif *netif, const ip4_addr_t *ipaddr, const ip4_addr_t
            *netmask, const ip4_addr_t *gw, void *state, netif_init_fn init, netif_input_fn input);
    int8_t (*tcpipinput)(struct pbuf *p, struct netif *inp);
    // XXX Right now only a tap interface is initialized
    RESOLVE_SYM(tapif_init,tapif_init,sd);
    RESOLVE_SYM(netif_add,netif_add,sd);
    RESOLVE_SYM(tcpipinput,tcpip_input,sd);
    netif_add(sd->netif,NULL,NULL,NULL,NULL,tapif_init,tcpipinput);
}

static int update_socket_events(int s, unsigned char events, void *arg, int *err) {
    // XXX as of this moment, using the emulation layer of vpoll, pollerr events can't really be
    // signaled
    struct stack_data *sd = (struct stack_data*) arg;
    struct fd_data *fdd;

    fdd = fduserdata_get(sd->sockets_data,s);
    if (fdd)
    {
        uint32_t sock_events = 0;
        if (SOCKEVENT_IS_POLLIN(events) && (fdd->ev.events && EPOLLIN))
            sock_events |= EPOLLIN;
        if (SOCKEVENT_IS_POLLOUT(events) && (fdd->ev.events && EPOLLOUT))
            sock_events |= EPOLLOUT;
        if (SOCKEVENT_IS_POLLERR(events) && (fdd->ev.events && EPOLLERR))
            sock_events |= EPOLLERR;
        vpoll_ctl(fdd->fd,VPOLL_CTL_SETEVENTS,sock_events);
        fduserdata_put(fdd);
        return 0;
    }
    else
    {
        *err = errno = EBADF;
        return -1;
    }
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

        void (*tcpip_init)(tcpip_init_done_fn, void *);
        RESOLVE_SYM(tcpip_init,tcpip_init,sd);
        int (*register_socket_event_callback)(int (*)(int, unsigned char, void*, int*), void*);
        RESOLVE_SYM(register_socket_event_callback,register_socket_event_callback,sd);

        tcpip_init(init_func,sd);
        register_socket_event_callback(update_socket_events,sd);

        *private_data = sd;
        return 0;
mem_error:
        if (sd) free(sd);
        dlclose(handle);
        errno = ENOMEM;
        return -1;
    }
}

static int vunetlwip_fini(void *private_data){
    struct stack_data *sd = private_data;
    void (*lock)(void);
    RESOLVE_SYM(lock,sys_lock_tcpip_core,sd);
    void (*unlock)(void);
    RESOLVE_SYM(unlock,sys_unlock_tcpip_core,sd);
    void (*netif_remove)(struct netif *);
    RESOLVE_SYM(netif_remove,netif_remove,sd);
    struct netif *netif_list;
    RESOLVE_SYM(netif_list,netif_list,sd);
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
