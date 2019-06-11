cmake_minimum_required(VERSION 3.8)

project(vpoll)

set(PROJECT_VERSION "0.9")

add_library(vpoll SHARED
    vpoll.c
    fduserdata.c
    )

target_include_directories(vpoll PRIVATE .)

set_target_properties(vpoll PROPERTIES VERSION ${PROJECT_VERSION}
    SOVERSION 1
    PUBLIC_HEADER vpoll.h
    )

install(TARGETS vpoll
    LIBRARY DESTINATION ${INSTALL_LIBDIR}
    PUBLIC_HEADER DESTINATION ${INSTALL_INCLUDEDIR}
)
