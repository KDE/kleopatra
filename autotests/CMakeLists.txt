# SPDX-FileCopyrightText: none
# SPDX-License-Identifier: BSD-3-Clause

include(ECMAddTests)

find_package(Qt6Test ${REQUIRED_QT_VERSION} CONFIG QUIET)

if(NOT TARGET Qt::Test)
    message(STATUS "Qt6Test not found, autotests will not be built.")
    return()
endif()

include_directories(${CMAKE_SOURCE_DIR}/src)

ecm_qt_declare_logging_category(logging_category_srcs HEADER kleopatra_debug.h IDENTIFIER KLEOPATRA_LOG CATEGORY_NAME org.kde.pim.kleopatra)

ecm_add_test(
    kuniqueservicetest.cpp
    ${CMAKE_SOURCE_DIR}/src/utils/kuniqueservice.cpp
    ${logging_category_srcs}
    TEST_NAME kuniqueservicetest
    LINK_LIBRARIES ${_kleopatra_dbusaddons_libs} Qt::Test
)

ecm_add_test(
    statusmessagetest.cpp
    ${CMAKE_SOURCE_DIR}/src/utils/statusmessage.cpp
    ${logging_category_srcs}
    TEST_NAME statusmessagetest
    LINK_LIBRARIES Qt::Test
)

ecm_add_test(
    stripsuffixtest.cpp
    ${CMAKE_SOURCE_DIR}/src/utils/path-helper.cpp
    ${logging_category_srcs}
    TEST_NAME stripsuffixtest
    LINK_LIBRARIES KF6::I18n KPim6::Libkleo Qt::Test
)
