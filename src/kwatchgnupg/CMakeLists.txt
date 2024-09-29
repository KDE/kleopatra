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
  tray.cpp
  ../utils/kuniqueservice.h
  ../kleopatra_debug.h
  kwatchgnupgmainwin.h
  kwatchgnupgconfig.h
  aboutdata.h
  tray.h
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

add_executable(kwatchgnupg ${kwatchgnupg_SRCS})
if (COMPILE_WITH_UNITY_CMAKE_SUPPORT)
    set_target_properties(kwatchgnupg PROPERTIES UNITY_BUILD ON)
endif()


target_link_libraries(kwatchgnupg
  KF6::DBusAddons
  KF6::XmlGui
  KF6::Notifications
  KF6::I18n
  KF6::IconThemes
  KPim6::Libkleo
  KF6::CoreAddons
  KF6::Crash
  KF6::StatusNotifierItem
)

install(TARGETS kwatchgnupg ${KDE_INSTALL_TARGETS_DEFAULT_ARGS})

install(FILES images/kwatchgnupg.png images/kwatchgnupg2.png DESTINATION ${KDE_INSTALL_DATADIR}/kwatchgnupg/pics)
install(FILES images/kwatchgnupg.png DESTINATION ${KDE_INSTALL_FULL_ICONDIR}/hicolor/22x22/apps)
install(FILES org.kde.kwatchgnupg.desktop DESTINATION ${KDE_INSTALL_APPDIR})
