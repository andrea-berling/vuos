#ifndef VUNETLWIP_H
#define VUNETLWIP_H

#include <lwip/netif.h>
#include <fduserdata.h>
#include <sys/epoll.h>

int lwip_accept(int s, struct sockaddr *addr, socklen_t *addrlen);
int lwip_bind(int s, const struct sockaddr *name, socklen_t namelen);
int lwip_shutdown(int s, int how);
int lwip_getpeername (int s, struct sockaddr *name, socklen_t *namelen);
int lwip_getsockname (int s, struct sockaddr *name, socklen_t *namelen);
int lwip_getsockopt (int s, int level, int optname, void *optval, socklen_t *optlen);
int lwip_setsockopt (int s, int level, int optname, const void *optval, socklen_t optlen);
 int lwip_close(int s);
int lwip_connect(int s, const struct sockaddr *name, socklen_t namelen);
int lwip_listen(int s, int backlog);
ssize_t lwip_recv(int s, void *mem, size_t len, int flags);
ssize_t lwip_read(int s, void *mem, size_t len);
ssize_t lwip_readv(int s, const struct iovec *iov, int iovcnt);
ssize_t lwip_recvfrom(int s, void *mem, size_t len, int flags,
      struct sockaddr *from, socklen_t *fromlen);
ssize_t lwip_recvmsg(int s, struct msghdr *message, int flags);
ssize_t lwip_send(int s, const void *dataptr, size_t size, int flags);
ssize_t lwip_sendmsg(int s, const struct msghdr *message, int flags);
ssize_t lwip_sendto(int s, const void *dataptr, size_t size, int flags,
    const struct sockaddr *to, socklen_t tolen);
int lwip_socket(int domain, int type, int protocol);
ssize_t lwip_write(int s, const void *dataptr, size_t size);
ssize_t lwip_writev(int s, const struct iovec *iov, int iovcnt);
int lwip_ioctl(int s, long cmd, void *argp);
int lwip_fcntl(int s, int cmd, int val);

err_t vdeif_init(struct netif *netif);
err_t tapif_init(struct netif *netif);

#define netif_get_index(netif)      ((u8_t)((netif)->num + 1))

#define NUM_SOCKETS MEMP_NUM_NETCONN
#define LIB_LWIP "liblwip.so"
#define MIN(x,y) (((x) > (y)) ? (x) : (y))

/* Overloading of RETRIEVE_SYM macro with 2 or 3 arguments */
#define GET_RETSYM( _1, _2, _3, NAME, ...) NAME
#define RETRIEVE_SYM(...) GET_RETSYM(__VA_ARGS__, RETSYM3, RETSYM2)(__VA_ARGS__)

/* 
 * In an expression like
 *
 * void f();
 *
 * ...
 *
 * typeof(f) *f = (typeof(f)) 0;
 *
 * we are defining a local variable f that points to the function f. Now, the first typeof refers to
 * the type of the function f, but the second typeof refers to the variable being defined, which is
 * already a pointer (another * would make it a double pointer). If the function was called g (or
 * anything other than f), the assignment would need to be
 *
 * typeof(g) *f = (typeof(g)*) 0;
 *
 * This happens when we want to retrieve a symbol from the lwip symbols table, and the name for the
 * pointer to the new symbol is the same as the name of the symbol (i.e. RETRIEVE_SYM with two
 * arguments). These macros use a concatenation trick to implement a sort of if-then-else which can
 * distinguish between the two cases and choose the right casting (this is the job of the
 * _RETSYM_TYPE macro)
 * 
 */
#define _PTR_TYPE(arg,cond) _PTR_TYPE_##cond(arg)
#define _PTR_TYPE_true(x) typeof(x)*
#define _PTR_TYPE_false(x) typeof(x)
#define _RETSYM3(newsym,symname,source,cond) \
    typeof(symname) *newsym = (_PTR_TYPE(symname,cond)) ((source)->lwipsymtab[symname##_IDX]);
#define RETSYM2(sym,source) _RETSYM3(sym,sym,source,false)
#define RETSYM3(newsym,symname,source) _RETSYM3(newsym,symname,source,true)

#define REDIRECT_TO_LWIP(sockfd,syscall,...) {\
    struct stack_data *sd = vunet_get_private_data(); \
    struct fd_data *fdd = fduserdata_get(sd->sockets_data,sockfd); \
    int lwipfd = fdd->fd; \
    int ret = 0; \
    fduserdata_put(fdd); \
    if (lwipfd >= 0) \
    { \
        /* need to relase fdd, as lwip may need to to signal events */ \
        RETRIEVE_SYM(lwip_##syscall,sd); \
        ret = lwip_##syscall(lwipfd,##__VA_ARGS__); \
    } \
    return ret; \
}

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
    HELPER_MACRO(register_socket_event_callback), \
    HELPER_MACRO(netif_default), \
    HELPER_MACRO(netif_set_default), \
    HELPER_MACRO(netif_set_gw), \
    HELPER_MACRO(vdeif_init)

/* In this macro x is purposedly written without parentheses around it to permit a return statement
   with nothing as an argument (e.g. in void functions). Use carefully
   */
#define DL_ERROR(x) do {\
    fprintf(stderr,"vunetlwip.c, line:%d, %s\n",__LINE__,dlerror());\
    return x;\
} while(0)

#define EFD_TBL_SIZE 64

#define HELPER_MACRO(X) X ## _IDX
enum { VUNETLWIP_SYMBOL_LIST, SYM_NUM };
#undef HELPER_MACRO

struct stack_data {
    void *handle;               // Handle to lwip.so symbols
    struct netif *netif;        // Network interfaces
    void *lwipsymtab[SYM_NUM]; // Lwip symbol table, to retrieve stack functions and variables
    FDUSERDATA *sockets_data;   // Used for event handling and Netlink sockets
    int lwip2efd[NUM_SOCKETS];   // Used to keep the map from lwip socket numbers to eventfd socket numbers
};

struct fd_data {
    struct epoll_event ev;      // Events virtualized processes are waiting on
    int fd;                     // lwip socket fd; if < 0, this is a netlink socket
    struct nlq_msg *msgq;       // Queue of Netlink messages for stack configuration
};

#endif /* VUNETLWIP_H */
