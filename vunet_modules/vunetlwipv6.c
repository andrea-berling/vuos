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
#include <lwipv6.h>
#include <vunet.h>

#if 0
Andrea: MAYBE DEPRECATED, in vuos there is an analogous in vunet_ioctl.c
static int vunetlwipv6_ioctlparms(int fd, int req, struct vunet *nethandle)
{
	switch (req) {
		case FIONREAD:
			return sizeof(int) | IOCTL_W;
		case FIONBIO:
			return sizeof(int) | IOCTL_R;
		case SIOCGIFCONF:
			return sizeof(struct ifconf) | IOCTL_R | IOCTL_W;
		case SIOCGSTAMP:
			return sizeof(struct timeval) | IOCTL_W;
		case SIOCGIFNAME:
		case SIOCGIFFLAGS:
		case SIOCGIFADDR:
		case SIOCGIFDSTADDR:
		case SIOCGIFBRDADDR:
		case SIOCGIFNETMASK:
		case SIOCGIFMETRIC:
		case SIOCGIFMEM:
		case SIOCGIFMTU:
		case SIOCGIFHWADDR:
		case SIOCGIFINDEX:
		case SIOCGIFTXQLEN:
			return sizeof(struct ifreq) | IOCTL_R | IOCTL_W;
		case SIOCSIFNAME:
		case SIOCSIFFLAGS:
		case SIOCSIFADDR:
		case SIOCSIFDSTADDR:
		case SIOCSIFBRDADDR:
		case SIOCSIFNETMASK:
		case SIOCSIFMETRIC:
		case SIOCSIFMEM:
		case SIOCSIFMTU:
		case SIOCSIFHWADDR:
		case SIOCSIFTXQLEN:
		case SIOCSIFHWBROADCAST:
			return sizeof(struct ifreq) | IOCTL_R;
		case SIOCGIFMAP:
			return sizeof(struct ifmap) | IOCTL_R | IOCTL_W;
		case SIOCSIFMAP:
			return sizeof(struct ifmap) | IOCTL_W;
		default:
			return 0;
	}
}
#endif

#if 0 /* temporarily disabled */
static int vunetlwipv6_ioctl(int d, unsigned long request, void *arg)
{
	if (request == SIOCGIFCONF) {
		int rv;
		void *save;
		struct ifconf *ifc=(struct ifconf *)arg;
		save=ifc->ifc_buf;
		ioctl(d,request,arg);
		ifc->ifc_buf=malloc(ifc->ifc_len);
		um_mod_umoven((long) save,ifc->ifc_len,ifc->ifc_buf);
		rv=lwip_ioctl(d,request,arg);
		if (rv>=0)
			um_mod_ustoren((long) save,ifc->ifc_len,ifc->ifc_buf);
		free(ifc->ifc_buf);
		ifc->ifc_buf=save;
		return rv;
	}
	return lwip_ioctl(d,request,arg);
}
#endif

static int vunetlwipv6_socket(int domain, int type, int protocol){
	struct stack *s= vunet_get_private_data();
	return lwip_msocket(s,domain, type, protocol);
}

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


int vunetlwipv6_init (const char *source, unsigned long flags, const char *args, void **private_data) {
	struct stack *s=lwip_stack_new();
	if (s) {
		lwipargtoenv(s,args);
		*private_data = s;
		return 0;
	} else {
		errno=EFAULT;
		return -1;
	}
}

int vunetlwipv6_fini (void *private_data){
	lwip_stack_free(private_data);
	return 0;
}

int vunetlwipv6_supported_domain(int domain)
{
	switch(domain) {
		case AF_INET:
		case PF_INET6:
		case PF_NETLINK:
		case PF_PACKET:
			return 1;
		default:
			return 0;
	}
}

struct vunet_operations vunet_ops={
	.socket=vunetlwipv6_socket,
	//.ioctl=vunetlwipv6_ioctl,
    .ioctl=lwip_ioctl,
	//VUNETLWIPV6(ioctl),
	//.ioctlparms=vunetlwipv6_ioctlparms,
	.init=vunetlwipv6_init,
	.fini=vunetlwipv6_fini,
	.supported_domain=vunetlwipv6_supported_domain,
	.bind = lwip_bind,
	.connect = lwip_connect,
	.listen = lwip_listen,
	//.accept4 = lwip_accept4,
	.getsockname = lwip_getsockname,
	.getpeername = lwip_getpeername,
	//VUNETLWIPV6S(sendmsg),
	//VUNETLWIPV6S(recvmsg),
	//VUNETLWIPV6S(sendto),
	//VUNETLWIPV6S(recvfrom),
	.sendmsg = lwip_sendmsg,
	.recvmsg = lwip_recvmsg,
	.shutdown = lwip_shutdown,
	.getsockopt = lwip_getsockopt,
	.setsockopt = lwip_setsockopt,
	//VUNETLWIPV6S(read),
	//VUNETLWIPV6S(write),
	.close = lwip_close,
	.epoll_ctl = lwip_epoll_ctl,
	//VUNETLWIPV6(event_subscribe),
};

#if 0
	static void
	__attribute__ ((constructor))
init (void)
{
	/*printk("vunetlwipv6 constructor\n");*/
}

	static void
	__attribute__ ((destructor))
fini (void)
{
	/*printk("vunetlwipv6 destructor\n");*/
}
#endif
