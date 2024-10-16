# SPDX-FileCopyrightText: none
# SPDX-License-Identifier: BSD-3-Clause

if(WIN32)
  set(_kleopatraclientcore_extra_SRCS ../../utils/gnupg-registry.c)
else()
  set(_kleopatraclientcore_extra_SRCS)
endif()

ecm_qt_declare_logging_category(_kleopatraclientcore_common_SRCS HEADER libkleopatraclientcore_debug.h IDENTIFIER LIBKLEOPATRACLIENTCORE_LOG CATEGORY_NAME org.kde.pim.libkleopatraclientcore
        DESCRIPTION "kleopatra client core (kleopatra)"
        OLD_CATEGORY_NAMES log_libkleopatraclientcore
        EXPORT KLEOPATRA
    )


add_library(kleopatraclientcore
  ${_kleopatraclientcore_extra_SRCS}
  command.cpp
  selectcertificatecommand.cpp
  libkleopatraclientcore_debug.cpp
  command.h
  selectcertificatecommand.h
  libkleopatraclientcore_debug.h
  ${_kleopatraclientcore_common_SRCS}
)
generate_export_header(kleopatraclientcore BASE_NAME kleopatraclientcore)

set_target_properties(kleopatraclientcore PROPERTIES
  VERSION ${libkleopatraclient_version}
  SOVERSION ${libkleopatraclient_soversion}
)
if (COMPILE_WITH_UNITY_CMAKE_SUPPORT)
    set_target_properties(kleopatraclientcore PROPERTIES UNITY_BUILD ON)
endif()

target_link_libraries(kleopatraclientcore LibAssuan::LibAssuan LibGpgError::LibGpgError Qt::Widgets KF6::I18n Gpgmepp)

install(TARGETS kleopatraclientcore ${KDE_INSTALL_TARGETS_DEFAULT_ARGS} LIBRARY NAMELINK_SKIP)
