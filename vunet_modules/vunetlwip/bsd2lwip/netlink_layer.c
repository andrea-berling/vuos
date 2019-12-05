#include <lwip_symbols.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <libnlq.h>
#include <lwip/tcpip.h>
#include <linux/if.h>
#include <strcase.h>
#include <bsd2lwip.h>

void *netif_netlink_searchlink(struct nlmsghdr *msg, struct nlattr **attr, void *handle) {
    struct stack_data *sd = (struct stack_data *) handle;
    struct ifinfomsg *ifi=(struct ifinfomsg *)(msg+1);
    RETRIEVE_SYM(netif_find,sd);
    RETRIEVE_SYM(netif_get_by_index,sd);
    RETRIEVE_SYM(lock,sys_lock_tcpip_core,sd);
    RETRIEVE_SYM(unlock,sys_unlock_tcpip_core,sd);
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
        RETRIEVE_SYM(netif_list,sd);
        for (nip = *netif_list; nip != NULL ; nip = nip->next) {
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
    RETRIEVE_SYM(lock,sys_lock_tcpip_core,sd);
    RETRIEVE_SYM(unlock,sys_unlock_tcpip_core,sd);
    RETRIEVE_SYM(netif_set_up,sd);
    RETRIEVE_SYM(netif_set_down,sd);

    lock();
    if (ifi->ifi_flags & IFF_UP)
        netif_set_up(nip);
    else
        netif_set_down(nip);
    unlock();
    return 0;
}

int netif_netlink_addlink(struct nlmsghdr *msg, struct nlattr **attr, void *stackinfo) {
    struct stack_data *sd = (struct stack_data *) stackinfo;

    RETRIEVE_SYM(vdeif_init,sd);
    RETRIEVE_SYM(netif_add,sd);
    RETRIEVE_SYM(tcpip_input,sd);
    RETRIEVE_SYM(lock,sys_lock_tcpip_core,sd);
    RETRIEVE_SYM(unlock,sys_unlock_tcpip_core,sd);

    if (attr[IFLA_INFO_KIND]) {
        struct netif *nif;
        netif_init_fn init_func;
        void *state;

        switch(strcase((char*)(attr[IFLA_INFO_KIND]+1)))
        {
            case STRCASE(v,d,e):
                init_func = vdeif_init;
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
        if (!nif) {
            return -ENOMEM;
        }
        else {
            lock();
            struct netif *ret = netif_add(nif, NULL, NULL, NULL, state, init_func, tcpip_input);
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
    RETRIEVE_SYM(lock,sys_lock_tcpip_core,sd);
    RETRIEVE_SYM(unlock,sys_unlock_tcpip_core,sd);
    RETRIEVE_SYM(netif_get_by_index,sd);
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
    RETRIEVE_SYM(lock,sys_lock_tcpip_core,sd);
    RETRIEVE_SYM(unlock,sys_unlock_tcpip_core,sd);
    RETRIEVE_SYM(netif_list,sd);
    RETRIEVE_SYM(netif_get_by_index,sd);
    lock();
    if (entry == NULL) {
        struct netif *nip = netif_get_by_index(ifa->ifa_index);
        for (nip = *netif_list; nip != NULL ; nip = nip->next)
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
    RETRIEVE_SYM(lock,sys_lock_tcpip_core,sd);
    RETRIEVE_SYM(unlock,sys_unlock_tcpip_core,sd);
    RETRIEVE_SYM(netif_get_by_index,sd);
    RETRIEVE_SYM(netif_set_addr,sd);
    RETRIEVE_SYM(netif_add_ip6_address,sd);
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
    RETRIEVE_SYM(lock,sys_lock_tcpip_core,sd);
    RETRIEVE_SYM(unlock,sys_unlock_tcpip_core,sd);
    RETRIEVE_SYM(netif_set_addr,sd);
    RETRIEVE_SYM(netif_ip6_addr_set_state,sd); lock();

    if (ipi->addr_idx < 0)
        netif_set_addr(ipi->nip,NULL,NULL,NULL);
    else
        netif_ip6_addr_set_state(ipi->nip, ipi->addr_idx, IP6_ADDR_INVALID);
    unlock();
    return 0;
}

void *netif_netlink_searchroute(struct nlmsghdr *msg, struct nlattr **attr, void *handle) {
    // XXX
    // as of 2.1.2, lwip doesn't support custom destination address routing
    // Routing for IPv4 works as follows: the interface to send the packet on, in the absence of
    // source routing, is the one with the IP address with the longest matching address prefix; if
    // no such interface exists, a default one is selected
    // Routing for IPv6 is more complex, and explained in detail in the doxygen comment of the
    // function ip6_route
    return NULL;
}

int netif_netlink_addroute(struct nlmsghdr *msg, struct nlattr **attr, void *stackinfo) {
    // XXX Only supports setting the default gateway for IPv4 as of right now (Tue 03 Dec 2019
    // 10:43:11 AM CET)
    struct stack_data *sd = (struct stack_data *) stackinfo;
    struct rtmsg *r = (struct rtmsg*)(msg+1);

    RETRIEVE_SYM(lock,sys_lock_tcpip_core,sd);
    RETRIEVE_SYM(unlock,sys_unlock_tcpip_core,sd);
    RETRIEVE_SYM(netif_default,sd);
    RETRIEVE_SYM(netif_set_gw,sd);

    if (r->rtm_family == AF_INET)
    {
        if (attr[RTA_DST])
            return -ENOTSUP;
        else if (attr[RTA_GATEWAY])
        {
            ip_addr_t gw;

            if (attr[RTA_GATEWAY]->nla_len == 8) {
                memcpy(&(ip_2_ip4(&gw)->addr),(int *)(attr[RTA_GATEWAY]+1),sizeof(uint32_t));
                lock();
                netif_set_gw(*netif_default,ip_2_ip4(&gw));
                unlock();
                return 0;
            }
            else
                return -EINVAL;
        }
        else
            return -EINVAL;
    }
    else
        return -ENOTSUP;
}

int netif_netlink_getroute(void *entry, struct nlmsghdr *msg, struct nlattr **attr, struct nlq_msg
        **reply_msgq, void *handle) {
    // XXX only replies with deafult IPv4 gateway for now (Tue 03 Dec 2019 11:54:00 AM CET)
    struct stack_data *sd = (struct stack_data *) handle;

    RETRIEVE_SYM(lock,sys_lock_tcpip_core,sd);
    RETRIEVE_SYM(unlock,sys_unlock_tcpip_core,sd);
    RETRIEVE_SYM(netif_default,sd);

    struct nlq_msg *newmsg = nlq_createmsg(RTM_NEWROUTE, 0, msg->nlmsg_seq, 0);
    nlq_addstruct(newmsg,rtmsg,
            .rtm_family = AF_INET,
            .rtm_scope = RT_SCOPE_UNIVERSE,
            .rtm_type = RTN_UNICAST,
            .rtm_table = RT_TABLE_MAIN
            );
    lock();
    u8_t tmp;
    tmp = RT_TABLE_MAIN;
    nlq_addattr(newmsg, RTA_TABLE, &tmp, sizeof(u8_t));
    nlq_addattr(newmsg, RTA_GATEWAY, netif_ip4_gw(*netif_default), sizeof(uint32_t));
    tmp = netif_get_index(*netif_default);
    nlq_addattr(newmsg, RTA_OIF, &tmp, sizeof(u8_t));
    unlock();
    nlq_complete_enqueue(newmsg, reply_msgq);

    return 0;
}

nlq_request_handlers_table handlers_table = {
    [RTMF_LINK]={netif_netlink_searchlink, netif_netlink_getlink, netif_netlink_addlink,
        NULL /*netif_netlink_dellink*/,  netif_netlink_setlink},
    [RTMF_ADDR]={netif_netlink_searchaddr, netif_netlink_getaddr, netif_netlink_addaddr,
        netif_netlink_deladdr, NULL},
    [RTMF_ROUTE]={netif_netlink_searchroute, netif_netlink_getroute, netif_netlink_addroute, NULL
        /*netif_netlink_delroute*/, NULL}
};
