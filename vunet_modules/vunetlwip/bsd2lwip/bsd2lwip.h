#ifndef BSD2LWIP_H
#define BSD2LWIP_H

#include <fduserdata.h>
#include <lwip_symbols.h>

#define netif_get_index(netif)      ((u8_t)((netif)->num + 1))

// XXX This has been taken literally from port/unix/lwiopts.h
#define MEMP_NUM_NETCONN               32

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

#define REDIRECT_TO_LWIP(sd,sockfd,syscall,...) {\
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
    int fd;                     // lwip socket fd; if < 0, this is a netlink socket
    struct nlq_msg *msgq;       // Queue of Netlink messages for stack configuration
};

typedef void (*init_func_t)(void *);

struct init_arg {
    struct stack_data *sd;
    void *arg;
};

int bsd2lwip_socket(struct stack_data *sd, int domain, int type, int protocol);
int bsd2lwip_bind(struct stack_data *sd, int sockfd, const struct sockaddr *addr, socklen_t addrlen);
int bsd2lwip_connect(struct stack_data *sd, int sockfd, const struct sockaddr *addr, socklen_t addrlen);
int bsd2lwip_listen(struct stack_data *sd, int sockfd, int backlog);
int bsd2lwip_accept4(struct stack_data *sd, int sockfd, struct sockaddr *addr, socklen_t *addrlen, int flags);
int bsd2lwip_getsockname(struct stack_data *sd, int sockfd, struct sockaddr *addr, socklen_t *addrlen);
int bsd2lwip_getpeername(struct stack_data *sd, int sockfd, struct sockaddr *addr, socklen_t *addrlen);
ssize_t bsd2lwip_recvfrom(void *buf, size_t len, int flags, struct sockaddr *from, socklen_t
        *fromlen, struct fd_data *fdd, int fd);
ssize_t bsd2lwip_recvmsg(struct stack_data *sd, int sockfd, struct msghdr *msg, int flags);
ssize_t bsd2lwip_sendto(struct stack_data *sd, const void *buf, size_t len, struct fd_data *fdd, int fd);
ssize_t bsd2lwip_sendmsg(struct stack_data *sd, int sockfd, const struct msghdr *msg, int flags);
int bsd2lwip_setsockopt(struct stack_data *sd, int sockfd, int level, int optname, const void *optval, socklen_t optlen);
int bsd2lwip_getsockopt(struct stack_data *sd, int sockfd, int level, int optname, void *optval, socklen_t *optlen);
int bsd2lwip_shutdown(struct stack_data *sd, int sockfd, int how);
int bsd2lwip_ioctl(struct stack_data *sd, int s, unsigned long cmd, void *argp);
int bsd2lwip_close(struct stack_data *sd, int fd);
int bsd2lwip_fcntl(struct stack_data *sd, int s, int cmd, long val);
void add_tap(void *arg);
struct stack_data *bsd2lwip_newstack(init_func_t init_func, void *arg);
int bsd2lwip_delstack(struct stack_data *sd);

#endif // BSD2LWIP_H
