cmake_minimum_required(VERSION 3.8)

project(fdutilities)

set(PROJECT_VERSION "0.9")

add_library(vpoll SHARED
    vpoll.c
    )

add_library(fduserdata SHARED
    fduserdata.c
    )

target_include_directories(vpoll PRIVATE .)
target_include_directories(fduserdata PRIVATE .)

target_link_libraries(vpoll fduserdata)

set_target_properties(vpoll PROPERTIES VERSION ${PROJECT_VERSION}
    SOVERSION 1
    PUBLIC_HEADER vpoll.h
    )

set_target_properties(fduserdata PROPERTIES VERSION ${PROJECT_VERSION}
    SOVERSION 1
    PUBLIC_HEADER fduserdata.h
    )

install(TARGETS vpoll
    LIBRARY DESTINATION ${INSTALL_LIBDIR}
    PUBLIC_HEADER DESTINATION ${INSTALL_INCLUDEDIR}
)

install(TARGETS fduserdata
    LIBRARY DESTINATION ${INSTALL_LIBDIR}
    PUBLIC_HEADER DESTINATION ${INSTALL_INCLUDEDIR}
)
