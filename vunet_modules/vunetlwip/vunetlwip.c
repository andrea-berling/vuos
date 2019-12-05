#include <vunet.h>
#include <bsd2lwip.h>

static int vunetlwip_socket(int domain, int type, int protocol) {
    struct stack_data *sd = (struct stack_data *) vunet_get_private_data();
    return bsd2lwip_socket(sd, domain, type, protocol);
}

static int vunetlwip_bind(int sockfd, const struct sockaddr * addr, socklen_t addrlen) {
    struct stack_data *sd = (struct stack_data *) vunet_get_private_data();
    return bsd2lwip_bind(sd, sockfd, addr, addrlen);
}

static int vunetlwip_connect(int sockfd, const struct sockaddr * addr, socklen_t addrlen) {
    struct stack_data *sd = (struct stack_data *) vunet_get_private_data();
    return bsd2lwip_connect(sd, sockfd, addr, addrlen);
}

static int vunetlwip_listen(int sockfd, int backlog) {
    struct stack_data *sd = (struct stack_data *) vunet_get_private_data();
    return bsd2lwip_listen(sd, sockfd, backlog);
}

// FIXME The flags are currently ignored
static int vunetlwip_accept4(int sockfd, struct sockaddr * addr, socklen_t * addrlen, int flags) {
    struct stack_data *sd = (struct stack_data *) vunet_get_private_data();
    return bsd2lwip_accept4(sd, sockfd, addr, addrlen, flags);
}

static int vunetlwip_getsockname(int sockfd, struct sockaddr * addr, socklen_t * addrlen) {
    struct stack_data *sd = (struct stack_data *) vunet_get_private_data();
    return bsd2lwip_getsockname(sd, sockfd, addr, addrlen);
}

static int vunetlwip_getpeername(int sockfd, struct sockaddr * addr, socklen_t * addrlen) {
    struct stack_data *sd = (struct stack_data *) vunet_get_private_data();
    return bsd2lwip_getpeername(sd, sockfd, addr, addrlen);
}

static ssize_t vunetlwip_recvmsg(int sockfd, struct msghdr * msg, int flags) {
    struct stack_data *sd = (struct stack_data *) vunet_get_private_data();
    return bsd2lwip_recvmsg(sd, sockfd, msg, flags);
}

static ssize_t vunetlwip_sendmsg(int sockfd, const struct msghdr * msg, int flags) {
    struct stack_data *sd = (struct stack_data *) vunet_get_private_data();
    return bsd2lwip_sendmsg(sd, sockfd, msg, flags);
}

// XXX There is a hook that can be defined to support options not provided by lwip. It may be
// useful
static int vunetlwip_setsockopt(int sockfd, int level, int optname, const void * optval, socklen_t  optlen) {
    struct stack_data *sd = (struct stack_data *) vunet_get_private_data();
    return bsd2lwip_setsockopt(sd, sockfd, level, optname, optval, optlen);
}

// XXX There is a hook that can be defined to support options not provided by lwip. May be
// useful
static int vunetlwip_getsockopt(int sockfd, int level, int optname, void * optval, socklen_t * optlen) {
    struct stack_data *sd = (struct stack_data *) vunet_get_private_data();
    return bsd2lwip_getsockopt(sd, sockfd, level, optname, optval, optlen);
}

static int vunetlwip_shutdown(int sockfd, int how) {
    struct stack_data *sd = (struct stack_data *) vunet_get_private_data();
    return bsd2lwip_shutdown(sd, sockfd, how);
}

static int vunetlwip_ioctl(int s, unsigned long cmd, void * argp) {
    struct stack_data *sd = (struct stack_data *) vunet_get_private_data();
    return bsd2lwip_ioctl(sd, s, cmd, argp);
}

static int vunetlwip_close(int fd) {
    struct stack_data *sd = (struct stack_data *) vunet_get_private_data();
    return bsd2lwip_close(sd, fd);
}

static int vunetlwip_fcntl(int s, int cmd, long val) {
    struct stack_data *sd = (struct stack_data *) vunet_get_private_data();
    return bsd2lwip_fcntl(sd, s, cmd, val);
}

static int vunetlwip_init(const char * source, unsigned long flags, const char * args, void ** private_data) {
    *private_data = bsd2lwip_newstack(add_tap,NULL);
    return 0;
}

static int vunetlwip_fini(void * private_data) {
    return bsd2lwip_delstack((struct stack_data *)private_data);
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
    .epoll_ctl = epoll_ctl,
    .supported_domain = vunetlwip_supported_domain,
    .supported_ioctl = vunetlwip_supported_ioctl,
    .init = vunetlwip_init,
    .fini = vunetlwip_fini
};
