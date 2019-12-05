cmake_minimum_required(VERSION 2.6)

include_directories(${VU_HEADERS} ${VU_DYN_HEADER_PATH})
set(LIBRARY_OUTPUT_PATH ${CMAKE_BINARY_DIR}/lib)
set(LIB_NAME bsd2lwip)
set(SRCS bsd2lwip.c netlink_layer.c)

add_library(${LIB_NAME} STATIC ${SRCS})
set_target_properties(${LIB_NAME} PROPERTIES PREFIX "")
target_link_libraries(${LIB_NAME} vpoll fduserdata nlq dl lwip)
set_property(TARGET ${LIB_NAME} PROPERTY POSITION_INDEPENDENT_CODE ON)
target_include_directories(${LIB_NAME} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}
                                             ../lwip/src/include/
                                             ../lwip/contrib/ports/unix/lib/
                                             ../lwip/contrib/ports/unix/port/include
                                             ../lwip/contrib/addons/socket_event
                                             )

