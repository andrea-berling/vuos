#include <lwip/tcpip.h>
#include <sys/ioctl.h>
#include <sys/epoll.h>
#include <dlfcn.h>
#include <socket_event.h>
#include <fduserdata.h>
#include <vpoll.h>
#include <libnlq.h>
#include <lwip_symbols.h>
#include <bsd2lwip.h>

#define HELPER_MACRO(X) #X
const char* lwip_sym_names[] = { VUNETLWIP_SYMBOL_LIST };
#undef HELPER_MACRO

extern nlq_request_handlers_table handlers_table;

int bsd2lwip_socket(struct stack_data *sd, int domain, int type, int protocol){
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

int bsd2lwip_bind(struct stack_data *sd, int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
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

int bsd2lwip_connect(struct stack_data *sd, int sockfd, const struct sockaddr *addr, socklen_t addrlen)
REDIRECT_TO_LWIP(sd,sockfd,connect,addr,addrlen)

int bsd2lwip_listen(struct stack_data *sd, int sockfd, int backlog) 
REDIRECT_TO_LWIP(sd,sockfd,listen,backlog)

// FIXME The flags are currently ignored
int bsd2lwip_accept4(struct stack_data *sd, int sockfd, struct sockaddr *addr, socklen_t *addrlen, int flags)
REDIRECT_TO_LWIP(sd,sockfd,accept,addr,addrlen)

int bsd2lwip_getsockname(struct stack_data *sd, int sockfd, struct sockaddr *addr, socklen_t *addrlen) {
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

int bsd2lwip_getpeername(struct stack_data *sd, int sockfd, struct sockaddr *addr, socklen_t *addrlen) 
REDIRECT_TO_LWIP(sd,sockfd,getpeername,addr,addrlen)

ssize_t bsd2lwip_recvfrom(void *buf, size_t len, int flags, struct sockaddr *from, socklen_t
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

ssize_t bsd2lwip_recvmsg(struct stack_data *sd, int sockfd, struct msghdr *msg, int flags) {
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
            ret = bsd2lwip_recvfrom(msg->msg_iov->iov_base, msg->msg_iov->iov_len, flags,
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
            size= bsd2lwip_recvfrom(lbuf,totalsize,flags, msg->msg_name, &(msg->msg_namelen), fdd, sockfd);
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

ssize_t bsd2lwip_sendto(struct stack_data *sd, const void *buf, size_t len, struct fd_data *fdd, int fd) {
    struct nlmsghdr *msg = (struct nlmsghdr *)buf;

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

ssize_t bsd2lwip_sendmsg(struct stack_data *sd, int sockfd, const struct msghdr *msg, int flags) {
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
            ret = bsd2lwip_sendto(sd,msg->msg_iov->iov_base,msg->msg_iov->iov_len,fdd, sockfd);
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
            size=bsd2lwip_sendto(sd,lbuf, totalsize, fdd, sockfd);
            ret = size;
        }
        fduserdata_put(fdd);
    }
    return ret;
}

// XXX There is a hook that can be defined to support options not provided by lwip. It may be
// useful
int bsd2lwip_setsockopt(struct stack_data *sd, int sockfd, int level, int optname, const void *optval, socklen_t optlen)
REDIRECT_TO_LWIP(sd,sockfd,setsockopt,level,optname,optval,optlen)

// XXX There is a hook that can be defined to support options not provided by lwip. May be
// useful
int bsd2lwip_getsockopt(struct stack_data *sd, int sockfd, int level, int optname, void *optval, socklen_t *optlen) 
REDIRECT_TO_LWIP(sd,sockfd,getsockopt,level,optname,optval,optlen)

int bsd2lwip_shutdown(struct stack_data *sd, int sockfd, int how) 
REDIRECT_TO_LWIP(sd,sockfd,shutdown,how)

int bsd2lwip_ioctl(struct stack_data *sd, int s, unsigned long cmd, void *argp) {
    if (s < 0)
        return vunet_is_netdev_ioctl(cmd) ? vunet_ioctl_parms(cmd) : -1;
    else
    {
        switch (cmd)
        {
            case FIONREAD:
            case FIONBIO:
                REDIRECT_TO_LWIP(sd,s,ioctl,cmd,argp)
                /* XXX I should probably make a separate case for SIOCGIFCONF, as in the vuos_example of
                 * libnlq */
            default:
                return nlq_server_ioctl(handlers_table, sd, cmd, argp);
        }
    }
}

int bsd2lwip_close(struct stack_data *sd, int fd) {
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

int bsd2lwip_fcntl(struct stack_data *sd, int s, int cmd, long val) 
REDIRECT_TO_LWIP(sd,s,fcntl,cmd,val)

int update_socket_events(int s, unsigned char events, void *arg, int *err) {
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
            if (SOCKEVENT_IS_POLLIN(events))
                sock_events |= EPOLLIN;
            if (SOCKEVENT_IS_POLLOUT(events))
                sock_events |= EPOLLOUT;
            if (SOCKEVENT_IS_POLLERR(events))
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

void add_tap(void *arg){
    struct stack_data *sd = ((struct init_arg *) arg)->sd;
    // Stack initialization
    struct netif *ret;
    // XXX As of right now only a tap interface is initialized
    RETRIEVE_SYM(tapif_init,sd);
    RETRIEVE_SYM(netif_add,sd);
    RETRIEVE_SYM(tcpip_input,sd);
    RETRIEVE_SYM(netif_set_default,sd);
    ret = netif_add(sd->netif,NULL,NULL,NULL,NULL,tapif_init,tcpip_input);
    if (ret)
        netif_set_default(ret);
}

/* Init func is called from inside the tcpip thread when the TCP initialization is done, with a
 * struct init_arg *, pointing to both the stack data and a custom argument */
struct stack_data *bsd2lwip_newstack(init_func_t init_func, void *arg) {
    void *handle;
    if ((handle = dlmopen(LM_ID_NEWLM,LIB_LWIP,RTLD_LAZY)) == NULL)
        DL_ERROR(NULL);
    else
    {
        unsigned i;
        struct stack_data *sd = calloc(1,sizeof(struct stack_data));
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
                if(sd->lwipsymtab[i] == NULL) goto mem_error;
            }
            if (i < NUM_SOCKETS)
                sd->lwip2efd[i] = -1;
        }

        RETRIEVE_SYM(tcpip_init,sd);
        RETRIEVE_SYM(register_socket_event_callback,sd);

        struct init_arg ia = {
            .sd = sd,
            .arg = arg
        };

        register_socket_event_callback(update_socket_events,sd);
        tcpip_init(init_func,(void *)&ia);

        return sd;
mem_error:
        if (sd) 
        {
            if (sd->sockets_data)
                fduserdata_destroy(sd->sockets_data);
            if (sd->netif)
                free(sd->netif);
            free(sd);
        }
        dlclose(handle);
        return NULL;
    }
}

int bsd2lwip_delstack(struct stack_data *sd){
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
            lwip_close(i);
    unlock();
    fduserdata_destroy(sd->sockets_data);
    dlclose(sd->handle);
    /*
     This could cause SEGFAULT in LwIP, as the tcpip thread keeps running. Need to propose a
     mechanism to LwIP
    free(sd->netif);
    free(sd);
    */
    return 0;
}
