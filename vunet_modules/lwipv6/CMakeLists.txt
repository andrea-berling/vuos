cmake_minimum_required(VERSION 3.8)

set(INSTALL_LIBDIR "/usr/lib")
set(INSTALL_INCLUDEDIR "/usr/include")
set(CONTRIBDIR "${CMAKE_CURRENT_SOURCE_DIR}/lwip-contrib")
set(LWIPDIR "${CMAKE_CURRENT_SOURCE_DIR}/lwip-v6/src")
set(LWIPARCH "${CONTRIBDIR}/ports/unix")
set(LWIPFILTERDIR "${LWIPDIR}/userfilter")
set(LWIPRADVDIR "${LWIPDIR}/radv")
set(VPOLLDIR "${CMAKE_CURRENT_SOURCE_DIR}/vpoll")

add_subdirectory(vpoll)
add_subdirectory(lwip-contrib/ports/unix/proj/lib)
add_subdirectory(lwipnc)
