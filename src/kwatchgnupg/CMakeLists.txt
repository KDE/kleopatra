# SPDX-FileCopyrightText: none
# SPDX-License-Identifier: BSD-3-Clause
set(kwatchgnupg_version 1.0)

find_package(KF6Notifications ${KF_MIN_VERSION} CONFIG REQUIRED)

configure_file(${CMAKE_CURRENT_SOURCE_DIR}/version-kwatchgnupg.h.in ${CMAKE_CURRENT_BINARY_DIR}/version-kwatchgnupg.h)

set(kwatchgnupg_SRCS
  ../utils/kuniqueservice.cpp
  ../kleopatra_debug.cpp
  kwatchgnupgmainwin.cpp
  kwatchgnupgconfig.cpp
  aboutdata.cpp
  ../utils/kuniqueservice.h
  ../kleopatra_debug.h
  kwatchgnupgmainwin.h
  kwatchgnupgconfig.h
  aboutdata.h
  main.cpp
  kwatchgnupg.qrc
)

ecm_qt_declare_logging_category(kwatchgnupg_SRCS HEADER kwatchgnupg_debug.h IDENTIFIER KWATCHGNUPG_LOG CATEGORY_NAME org.kde.pim.kwatchgnupg
        DESCRIPTION "kwatchgnupg (kwatchgnupg)"
        OLD_CATEGORY_NAMES log_kwatchgnupg
        EXPORT KLEOPATRA
    )

if(WIN32)
  set(kwatchgnupg_SRCS ${kwatchgnupg_SRCS} ../utils/gnupg-registry.c)
endif()

file(GLOB ICONS_SRCS "${CMAKE_CURRENT_SOURCE_DIR}/images/*-apps-org.kde.kwatchgnupg.*")
ecm_add_app_icon(kwatchgnupg_SRCS ICONS ${ICONS_SRCS})
ecm_install_icons(ICONS ${ICONS_SRCS} DESTINATION ${KDE_INSTALL_ICONDIR})

add_executable(kwatchgnupg ${kwatchgnupg_SRCS})
if (COMPILE_WITH_UNITY_CMAKE_SUPPORT)
    set_target_properties(kwatchgnupg PROPERTIES UNITY_BUILD ON)
endif()


target_link_libraries(kwatchgnupg
  ${_kleopatra_dbusaddons_libs}
  KF6::XmlGui
  KF6::Notifications
  KF6::I18n
  KPim6::Libkleo
  KF6::CoreAddons
  KF6::Crash
  KF6::WindowSystem
)

install(TARGETS kwatchgnupg ${KDE_INSTALL_TARGETS_DEFAULT_ARGS})
install(FILES org.kde.kwatchgnupg.desktop DESTINATION ${KDE_INSTALL_APPDIR})
