cmake_minimum_required(VERSION 3.0...4.2)
project(ranpwd
    VERSION 2.0
    DESCRIPTION "Simple password generator"
    HOMEPAGE_URL https://github.com/overcq/ranpwd
    LANGUAGES C
)

include(CheckFunctionExists)
include(CheckIncludeFiles)
include(GNUInstallDirs)

###############################################################################
# Project configuration

set(CMAKE_INCLUDE_CURRENT_DIR ON)

check_include_files("getopt.h" HAVE_GETOPT_H)
if(HAVE_GETOPT_H)
    check_function_exists(getopt_long HAVE_GETOPT_LONG)
endif()

###############################################################################
# Build rules

configure_file(config.h.in ${CMAKE_CURRENT_BINARY_DIR}/config.h)

add_executable(${PROJECT_NAME} main.c random.c)

###############################################################################
# Install rules

set(CMAKE_INSTALL_PREFIX /usr)

install(
    TARGETS ${PROJECT_NAME}
    DESTINATION ${CMAKE_INSTALL_BINDIR}
)

install(
    FILES ${PROJECT_NAME}.1
    DESTINATION ${CMAKE_INSTALL_MANDIR}/man1
)
