cmake_minimum_required(VERSION 3.8)

set(LWIPNCS lwipnc-poll lwipnc-epoll lwipnc-select)

foreach(LWIPNC ${LWIPNCS})
    add_executable(${LWIPNC} "${LWIPNC}.c")
    target_include_directories("${LWIPNC}" PRIVATE "${LWIPARCH}/include")
    target_link_libraries(${LWIPNC} lwipv6 dl pthread vpoll fduserdata)
endforeach(LWIPNC)
