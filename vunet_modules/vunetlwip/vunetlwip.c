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
#include <sys/un.h>
#include <signal.h>
#include <vunetlwip.h>

#define HELPER_MACRO(X) #X
const char* lwip_sym_names[] = { VUNETLWIP_SYMBOL_LIST };
#undef HELPER_MACRO

extern nlq_request_handlers_table handlers_table;

static int vunetlwip_socket(int domain, int type, int protocol){
    struct stack_data *sd = vunet_get_private_data();
    int idx = -1,fd;
    RETRIEVE_SYM(lwip_socket,sd);
    if (domain != AF_NETLINK)
    {
        /* lwip assumes that every SOCK_DGRAM socket is a UDP socket. Thus, when DGRAM is used to
         * open a ICMP socket lwip actually opens a UDP one, and sends UDP packet, with unwanted
         * results. Here we change the type to SOCK_RAW. The best thing would be to support this
         * case directly in lwip */
        if (type == SOCK_DGRAM && protocol == IPPROTO_ICMP)
            type = SOCK_RAW;

        idx = lwip_socket(domain,type,protocol);
    }

    fd = vpoll_create(EPOLLOUT,0); /* The socket is ready for packet sending */

    RETRIEVE_SYM(lwip_close,sd);

    if (fd < 0) {
        if (idx >= 0) lwip_close(idx);
        errno = ENOMEM;
        return -1;
    }
    else
    {
        struct fd_data *fdd = fduserdata_new(sd->sockets_data,fd,struct fd_data);
        if (!fdd)
        {
            close(fd); 
            if (idx >= 0) {
                fduserdata_put(fdd);
                lwip_close(idx);
            }
            errno = ENOMEM;
            return -1;
        }
        else
        {
            fdd->fd = idx;
            if (idx >= 0)
                sd->lwip2efd[idx] = fd;
            fdd->msgq = NULL;
            fduserdata_put(fdd);
            return fd;
        }
    }
}

static int vunetlwip_bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
    struct stack_data *sd = vunet_get_private_data();
    struct fd_data *fdd = fduserdata_get(sd->sockets_data,sockfd);
    int lwipfd = fdd->fd;
    int ret = 0;

    fduserdata_put(fdd);

    if (lwipfd >= 0)
    {
        RETRIEVE_SYM(lwip_bind,sd);
        ret = lwip_bind(lwipfd,addr,addrlen);
    }
    return ret;
}

static int vunetlwip_connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
REDIRECT_TO_LWIP(sockfd,connect,addr,addrlen)

static int vunetlwip_listen(int sockfd, int backlog) 
REDIRECT_TO_LWIP(sockfd,listen,backlog)

// FIXME The flags are currently ignored
static int vunetlwip_accept4(int sockfd, struct sockaddr *addr, socklen_t *addrlen, int flags)
REDIRECT_TO_LWIP(sockfd,accept,addr,addrlen)

static int vunetlwip_getsockname(int sockfd, struct sockaddr *addr, socklen_t *addrlen) {
    struct stack_data *sd = vunet_get_private_data();
    struct fd_data *fdd = fduserdata_get(sd->sockets_data,sockfd);
    int ret;
    int lwipfd = fdd->fd;
    fduserdata_put(fdd);
    if (lwipfd >= 0)
    {
        RETRIEVE_SYM(lwip_getsockname,sd);
        ret = lwip_getsockname(fdd->fd,addr,addrlen);
    }
    else
    {
        struct sockaddr_nl *raddr = (struct sockaddr_nl *) addr;
        raddr->nl_family = AF_NETLINK;
        raddr->nl_pad = 0;
        raddr->nl_pid = 0;
        raddr->nl_groups = 0;
        *addrlen = sizeof(struct sockaddr_nl);
        ret = 0;
    }
    return ret;
}

static int vunetlwip_getpeername(int sockfd, struct sockaddr *addr, socklen_t *addrlen) 
REDIRECT_TO_LWIP(sockfd,getpeername,addr,addrlen)

static ssize_t vunetlwip_recvfrom(void *buf, size_t len, int flags, struct sockaddr *from, socklen_t
        *fromlen, struct fd_data *fdd, int fd)
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
            vpoll_ctl(fd,VPOLL_CTL_DELEVENTS,EPOLLIN);
    }
    if (fromlen && *fromlen >= sizeof(struct sockaddr_nl)) {
        struct sockaddr_nl *socknl = (struct sockaddr_nl *)from;
        socknl->nl_family = AF_NETLINK;
        socknl->nl_pad = 0;
        socknl->nl_pid = 0;
        socknl->nl_groups = 0;
        *fromlen = sizeof(struct sockaddr_nl);
    }
    return retval;
}

static ssize_t vunetlwip_recvmsg(int sockfd, struct msghdr *msg, int flags) {
    struct stack_data *sd = vunet_get_private_data();
    struct fd_data *fdd = fduserdata_get(sd->sockets_data,sockfd);
    int lwipfd = fdd->fd;
    int ret;
    if (lwipfd >= 0)
    {
        RETRIEVE_SYM(lwip_recvmsg,sd);
        fduserdata_put(fdd);
        ret = lwip_recvmsg(lwipfd,msg,flags);
    }
    else
    {
        msg->msg_controllen=0;
        if (msg->msg_iovlen == 1) {
            ret = vunetlwip_recvfrom(msg->msg_iov->iov_base, msg->msg_iov->iov_len, flags,
                    msg->msg_name, &(msg->msg_namelen), fdd, sockfd);
            if (ret > msg->msg_iov->iov_len)
                msg->msg_flags |= MSG_TRUNC;
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
            size= vunetlwip_recvfrom(lbuf,totalsize,flags, msg->msg_name, &(msg->msg_namelen), fdd, sockfd);
            if (size > totalsize)
                msg->msg_flags |= MSG_TRUNC;
            for (i=0;size > 0 && i<msg_iovlen;i++) {
                int qty=(size > msg_iov[i].iov_len)?msg_iov[i].iov_len:size;
                memcpy(msg_iov[i].iov_base,lbuf,qty);
                lbuf+=qty;
                size-=qty;
            }
            ret = size;
        }
        fduserdata_put(fdd);
    }
    return ret;
}

static ssize_t vunetlwip_sendto(const void *buf, size_t len, struct fd_data *fdd, int fd) {
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
        vpoll_ctl(fd,VPOLL_CTL_ADDEVENTS, EPOLLIN);
    return len;
}

static ssize_t vunetlwip_sendmsg(int sockfd, const struct msghdr *msg, int flags) {
    struct stack_data *sd = vunet_get_private_data();
    struct fd_data *fdd = fduserdata_get(sd->sockets_data,sockfd);
    int lwipfd = fdd->fd;
    int ret;
    if (lwipfd >= 0)
    {
        RETRIEVE_SYM(lwip_sendmsg,sd);
        fduserdata_put(fdd);
        ret = lwip_sendmsg(lwipfd,msg,flags);
    }
    else
    {
        //msg->msg_controllen=0;
        if (msg->msg_iovlen == 1) {
            ret = vunetlwip_sendto(msg->msg_iov->iov_base,msg->msg_iov->iov_len,fdd, sockfd);
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
            size=vunetlwip_sendto(lbuf, totalsize, fdd, sockfd);
            ret = size;
        }
        fduserdata_put(fdd);
    }
    return ret;
}

// XXX There is a hook that can be defined to support options not provided by lwip. It may be
// useful
static int vunetlwip_setsockopt(int sockfd, int level, int optname, const void *optval, socklen_t optlen)
REDIRECT_TO_LWIP(sockfd,setsockopt,level,optname,optval,optlen)

// XXX There is a hook that can be defined to support options not provided by lwip. May be
// useful
static int vunetlwip_getsockopt(int sockfd, int level, int optname, void *optval, socklen_t *optlen) 
REDIRECT_TO_LWIP(sockfd,getsockopt,level,optname,optval,optlen)

static int vunetlwip_shutdown(int sockfd, int how) 
REDIRECT_TO_LWIP(sockfd,shutdown,how)

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
                REDIRECT_TO_LWIP(s,ioctl,cmd,argp)
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
    int lwipfd = fdd->fd;
    int ret = 0;

    if (fdd) fduserdata_del(fdd);

    if (lwipfd >= 0)
    {
        sd->lwip2efd[lwipfd] = MIN(-1,sd->lwip2efd[lwipfd]);
        RETRIEVE_SYM(lwip_close,sd);
        ret = lwip_close(lwipfd);
    }

    return ret;
}

static int vunetlwip_fcntl(int s, int cmd, long val) 
REDIRECT_TO_LWIP(s,fcntl,cmd,val)

static int vunetlwip_epoll_ctl(int epfd, int op, int fd, struct epoll_event *event) {
    struct stack_data *sd = vunet_get_private_data();
    struct fd_data *fdd;
    if ((fdd = fduserdata_get(sd->sockets_data,fd)) == NULL)
        return -1;
    else
    {
        fdd->ev.events = event ? event->events : 0;
        epoll_ctl(epfd,op,fd,event);
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

static int update_socket_events(int s, unsigned char events, void *arg, int *err) {
    // XXX as of this moment, using the emulation layer of vpoll, pollerr events can't really be
    // signaled
    struct stack_data *sd = (struct stack_data*) arg;
    struct fd_data *fdd;
    int fd;
    if ((fd = sd->lwip2efd[s]) > -1)
    {
        fdd = fduserdata_get(sd->sockets_data,fd);
        if (fdd)
        {
            uint32_t sock_events = 0;
            if (SOCKEVENT_IS_POLLIN(events) && (fdd->ev.events && EPOLLIN))
                sock_events |= EPOLLIN;
            if (SOCKEVENT_IS_POLLOUT(events) && (fdd->ev.events && EPOLLOUT))
                sock_events |= EPOLLOUT;
            if (SOCKEVENT_IS_POLLERR(events) && (fdd->ev.events && EPOLLERR))
                sock_events |= EPOLLERR;
            vpoll_ctl(fd,VPOLL_CTL_SETEVENTS,sock_events);
            fduserdata_put(fdd);
            return 0;
        }
        else
        {
            fduserdata_put(fdd);
            return *err = errno = EBADF,-1;
        }
    }
    else
        return *err = errno = EBADF,-1;
}

static void init_func(void *arg){
    struct stack_data *sd = (struct stack_data *) arg;
    // Stack initialization
    struct netif *ret;
    // XXX As of right now only a tap interface is initialized
    RETRIEVE_SYM(tapif_init,sd);
    RETRIEVE_SYM(netif_add,sd);
    RETRIEVE_SYM(tcpip_input,sd);
    RETRIEVE_SYM(netif_set_default,sd);
    RETRIEVE_SYM(register_socket_event_callback,sd);
    ret = netif_add(sd->netif,NULL,NULL,NULL,NULL,tapif_init,tcpip_input);
    if (ret)
        netif_set_default(ret);
    register_socket_event_callback(update_socket_events,sd);
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
        sd->netif = calloc(1,sizeof(struct netif));
        if (!sd->netif) goto mem_error;
        for(i = 0; i < SYM_NUM || i < NUM_SOCKETS; i++) /* Recycling a for */
        {
            if (i < SYM_NUM)
            {
                sd->lwipsymtab[i] = dlsym(handle,lwip_sym_names[i]);
                if(sd->lwipsymtab[i] == NULL)
                {
                    DL_ERROR(-1);
                    free(sd);
                    dlclose(handle);
                }
            }
            if (i < NUM_SOCKETS)
                sd->lwip2efd[i] = -1;
        }

        RETRIEVE_SYM(tcpip_init,sd);

        tcpip_init(init_func,sd);

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
    struct netif *nip;
    int i;

    RETRIEVE_SYM(lock,sys_lock_tcpip_core,sd);
    RETRIEVE_SYM(unlock,sys_unlock_tcpip_core,sd);
    RETRIEVE_SYM(netif_remove,sd);
    RETRIEVE_SYM(netif_list,sd);
    RETRIEVE_SYM(lwip_close,sd);

    lock();
    /* Removing the interfaces */
    for (nip = *netif_list; nip != NULL ; nip = nip->next)
        netif_remove(nip);
    for (i = 0; i < NUM_SOCKETS; i++)
        if (sd->lwip2efd[i] >= 0)
        {
            lwip_close(i);
            sd->lwip2efd[i] = -1;
        }
    unlock();
    fduserdata_destroy(sd->sockets_data);
    dlclose(sd->handle);
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
