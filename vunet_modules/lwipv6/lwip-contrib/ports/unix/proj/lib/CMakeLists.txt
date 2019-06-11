# created on 2019-04-28 using the following SO answer:
# https://stackoverflow.com/questions/17511496/how-to-create-a-shared-library-with-cmake
cmake_minimum_required(VERSION 3.8)
project(lwipv6 VERSION 1.5 DESCRIPTION "A lightweight TCP/IP stack")

set(PROJECT_VERSION "1.5")

include_directories(
    ${LWIPDIR}/include
    ${LWIPDIR}/include/userfilter
    ${LWIPDIR}/include/ipv6
    ${LWIPDIR}/include/radv
    ${LWIPARCH}/include
    ${VPOLLDIR}
    ${CMAKE_CURRENT_SOURCE_DIR}
    )

add_library(lwipv6 SHARED 
    # COREFILES
    ${LWIPDIR}/core/mem_malloc.c
    ${LWIPDIR}/core/memp_malloc.c
    ${LWIPDIR}/core/pbufnopool.c
	${LWIPDIR}/core/netif.c
	${LWIPDIR}/core/stats.c
	${LWIPDIR}/core/sys.c
	${LWIPDIR}/core/tcp.c
	${LWIPDIR}/core/tcp_in.c
	${LWIPDIR}/core/tcp_out.c
	${LWIPDIR}/core/udp.c
	${LWIPDIR}/core/raw.c
	${LWIPDIR}/core/packet.c
	${LWIPDIR}/core/dhcp.c
	${LWIPDIR}/core/lwslirp.c
    # CORE6FILES
    ${LWIPDIR}/core/inet6.c
    ${LWIPDIR}/core/ipv6/icmp6.c
    ${LWIPDIR}/core/ipv6/ip6.c
    ${LWIPDIR}/core/ipv6/ip6_addr.c
    ${LWIPDIR}/core/ipv6/ip6_route.c
    ${LWIPDIR}/core/ipv6/ip6_frag.c
    ${LWIPDIR}/core/ipv6/ip6_autoconf.c
    ${LWIPDIR}/core/ipv6/ip6_radv.c
    # APIFILES
    ${LWIPDIR}/api/api_lib.c
	${LWIPDIR}/api/api_msg.c
	${LWIPDIR}/api/tcpip.c
	${LWIPDIR}/api/err.c
	${LWIPDIR}/api/netlink.c
	${LWIPDIR}/api/sockets.c
    # NETIFFILES
    ${LWIPDIR}/netif/loopif.c
	${LWIPDIR}/netif/etharp.c
    # ARCHFILES
    ${LWIPARCH}/sys_arch_pipe.c
    #${LWIPARCH}/sys_arch.2sem.c
    #${LWIPARCH}/sys_arch.c
    ${LWIPARCH}/netif/vdeif.c
    ${LWIPARCH}/netif/slirpif.c
    ${LWIPARCH}/netif/tapif.c
    ${LWIPARCH}/netif/tunif.c
    # LWIPFILTERFILES
    ${LWIPFILTERDIR}/userfilter.c
	${LWIPFILTERDIR}/nat/nat.c
	${LWIPFILTERDIR}/nat/nat_rules.c
	${LWIPFILTERDIR}/nat/nat_tables.c
	${LWIPFILTERDIR}/nat/nat_track_proto_tcp.c
	${LWIPFILTERDIR}/nat/nat_track_proto_udp.c
	${LWIPFILTERDIR}/nat/nat_track_proto_icmp4.c
	${LWIPFILTERDIR}/nat/nat_track_proto_generic.c
    # RADVFILES
    ${LWIPRADVDIR}/radvconf.c
    #sharedlib.c
    unixlib.c
    )
 
set_target_properties(lwipv6    PROPERTIES VERSION ${PROJECT_VERSION} SOVERSION 1 PUBLIC_HEADER
    ${LWIPARCH}/include/lwipv6.h)

target_link_libraries(vpoll)

install(TARGETS lwipv6
    LIBRARY DESTINATION ${INSTALL_LIBDIR}
    PUBLIC_HEADER DESTINATION ${INSTALL_INCLUDEDIR})
