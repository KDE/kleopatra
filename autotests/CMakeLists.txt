# SPDX-FileCopyrightText: none
# SPDX-License-Identifier: BSD-3-Clause

include(ECMAddTests)

find_package(Qt${QT_MAJOR_VERSION}Test ${REQUIRED_QT_VERSION} CONFIG QUIET)

if(NOT TARGET Qt::Test)
    message(STATUS "Qt${QT_MAJOR_VERSION}Test not found, autotests will not be built.")
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
    pathhelpertest.cpp
    ${CMAKE_SOURCE_DIR}/src/utils/path-helper.cpp
    ${logging_category_srcs}
    TEST_NAME pathhelpertest
    LINK_LIBRARIES KF${KF_MAJOR_VERSION}::I18n KPim${KF_MAJOR_VERSION}::Libkleo Qt::Test
)

ecm_add_test(
    keyparameterstest.cpp
    ${CMAKE_SOURCE_DIR}/src/utils/keyparameters.cpp
    ${logging_category_srcs}
    TEST_NAME keyparameterstest
    LINK_LIBRARIES KPim${KF_MAJOR_VERSION}::Libkleo Gpgmepp Qt::Test
)
