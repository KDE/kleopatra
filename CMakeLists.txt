# SPDX-FileCopyrightText: none
# SPDX-License-Identifier: BSD-3-Clause
cmake_minimum_required(VERSION 3.16 FATAL_ERROR)

set(RELEASE_SERVICE_VERSION_MAJOR "26")
set(RELEASE_SERVICE_VERSION_MINOR "03")
set(RELEASE_SERVICE_VERSION_MICRO "70")

set(RELEASE_SERVICE_VERSION "${RELEASE_SERVICE_VERSION_MAJOR}.${RELEASE_SERVICE_VERSION_MINOR}.${RELEASE_SERVICE_VERSION_MICRO}")
if(RELEASE_SERVICE_VERSION_MICRO LESS 10)
    set(KDE_APPLICATIONS_COMPACT_VERSION "${RELEASE_SERVICE_VERSION_MAJOR}${RELEASE_SERVICE_VERSION_MINOR}0${RELEASE_SERVICE_VERSION_MICRO}")
else()
    set(KDE_APPLICATIONS_COMPACT_VERSION "${RELEASE_SERVICE_VERSION_MAJOR}${RELEASE_SERVICE_VERSION_MINOR}${RELEASE_SERVICE_VERSION_MICRO}")
endif()

set(KLEOPATRA_VERSION_MAJOR "4")
set(KLEOPATRA_VERSION_MINOR "0")
set(KLEOPATRA_VERSION_MICRO "0")

set(kleopatra_version "${KLEOPATRA_VERSION_MAJOR}.${KLEOPATRA_VERSION_MINOR}.${KLEOPATRA_VERSION_MICRO}.${KDE_APPLICATIONS_COMPACT_VERSION}")
# KLEOPATRA_VERSION_STRING is used for the About data; Gpg4win sets it to a custom value
if (NOT KLEOPATRA_VERSION_STRING)
    set(KLEOPATRA_VERSION_STRING "${kleopatra_version}")
endif()
# The following is for Windows
set(kleopatra_version_win "${KLEOPATRA_VERSION_MAJOR}.${KLEOPATRA_VERSION_MINOR}.${KLEOPATRA_VERSION_MICRO}")
set(kleopatra_fileversion_win "${KLEOPATRA_VERSION_MAJOR},${KLEOPATRA_VERSION_MINOR},${KLEOPATRA_VERSION_MICRO},0")
if (NOT KLEOPATRA_DISTRIBUTION_TEXT)
    # This is only used on Windows for the file attributes of Kleopatra
    set(KLEOPATRA_DISTRIBUTION_TEXT "KDE")
endif()
if (NOT KLEOPATRA_ORGANIZATION_DOMAIN)
    # This is used to allow multiple flavors of Kleopatra to run at the same time on Windows
    set(KLEOPATRA_ORGANIZATION_DOMAIN "kde.org")
endif()
if (KLEOPATRA_LIST_AS_COMPONENT)
    set(KLEOPATRA_LIST_AS_COMPONENT 1)
endif()

project(kleopatra VERSION ${kleopatra_version})

option(DISABLE_KWATCHGNUPG "Don't build the kwatchgnupg tool [default=OFF]" OFF)

# Standalone build. Find / include everything necessary.
set(KF_MIN_VERSION "6.20.0")
set(KIDENTITYMANAGEMENT_VERSION "6.6.40")
set(KMAILTRANSPORT_VERSION "6.6.40")
set(AKONADI_MIME_VERSION "6.6.40")
set(KMIME_VERSION "6.6.40")
set(LIBKLEO_VERSION "6.6.41")
set(QT_REQUIRED_VERSION "6.7.0")
set(MIMETREEPARSER_VERSION "6.6.40")
set(GPGME_REQUIRED_VERSION "1.23.2")
set(LIBASSUAN_REQUIRED_VERSION "2.4.2")
set(GPG_ERROR_REQUIRED_VERSION "1.36")

if (WIN32)
  set(KF6_WANT_VERSION ${KF_MIN_VERSION})
  set(KMIME_WANT_VERSION ${KMIME_VERSION})
else ()
  set(KF6_WANT_VERSION ${KF_MIN_VERSION})
  set(KMIME_WANT_VERSION ${KMIME_VERSION})
endif ()

set(CMAKE_CXX_SCAN_FOR_MODULES OFF)

find_package(ECM ${KF6_WANT_VERSION} CONFIG REQUIRED)
set(CMAKE_MODULE_PATH ${ECM_MODULE_PATH})
set(CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/cmake/modules ${CMAKE_MODULE_PATH})

include(ECMInstallIcons)
include(ECMSetupVersion)
include(ECMAddTests)
include(GenerateExportHeader)
include(ECMGenerateHeaders)
include(CheckFunctionExists)
include(KDEInstallDirs)
include(KDECMakeSettings)
include(KDECompilerSettings NO_POLICY_SCOPE)
include(ECMAddAppIcon)
include(ECMQtDeclareLoggingCategory)
include(ECMDeprecationSettings)
include(ECMFeatureSummary)
include(KDEClangFormat)
include(KDEGitCommitHooks)

# Find KF6 packages
find_package(KF6 ${KF6_WANT_VERSION}
    REQUIRED COMPONENTS
    Codecs
    ColorScheme
    Config
    CoreAddons
    Crash
    I18n
    IconThemes
    ItemModels
    KIO
    WidgetsAddons
    WindowSystem
    XmlGui

    OPTIONAL_COMPONENTS
    DocTools
)

set_package_properties(KF6DocTools PROPERTIES
    DESCRIPTION "Documentation tools"
    PURPOSE "Required to generate Kleopatra documentation."
    TYPE OPTIONAL)

# Optional packages
# shall we use DBus?
# enabled per default on Linux & BSD systems
set(USE_DBUS_DEFAULT OFF)
if(UNIX AND NOT APPLE AND NOT ANDROID AND NOT HAIKU)
    set(USE_DBUS_DEFAULT ON)
endif()
option(USE_DBUS "Build components using DBus (used for interprocess communication, external open in same instance and various presentation related bits)" ${USE_DBUS_DEFAULT})
if(USE_DBUS)
  find_package(KF6DBusAddons ${KF6_WANT_VERSION} CONFIG REQUIRED)
  set(_kleopatra_dbusaddons_libs KF6::DBusAddons)
  set(HAVE_QDBUS 1)
endif()


find_package(Gpgmepp ${GPGME_REQUIRED_VERSION} CONFIG REQUIRED)
set(QGPGME_NAME "QGpgmeQt6")
find_package(${QGPGME_NAME} ${GPGME_REQUIRED_VERSION} CONFIG REQUIRED)
if (${QGPGME_NAME}_VERSION VERSION_GREATER_EQUAL "1.24.0")
    set(QGPGME_FILE_JOBS_SUPPORT_DIRECT_FILE_IO 1)
    set(QGPGME_IMPORT_JOB_SUPPORTS_IMPORT_OPTIONS 1)
    set(QGPGME_SUPPORTS_PROCESS_ALL_SIGNATURES 1)
endif()

find_package(KPim6Libkleo ${LIBKLEO_VERSION} CONFIG REQUIRED)
find_package(KPim6Mime ${KMIME_WANT_VERSION} CONFIG REQUIRED)
find_package(KPim6IdentityManagementCore ${KIDENTITYMANAGEMENT_VERSION} CONFIG)
find_package(KPim6MailTransport ${KMAILTRANSPORT_VERSION} CONFIG)
find_package(KPim6AkonadiMime ${AKONADI_MIME_VERSION} CONFIG)
find_package(KPim6MimeTreeParserWidgets ${MIMETREEPARSER_VERSION} CONFIG REQUIRED)

set(CMAKE_MODULE_PATH ${LIBKLEO_MODULE_PATH} ${CMAKE_MODULE_PATH})

find_package(Qt6 ${QT_REQUIRED_VERSION} CONFIG REQUIRED Widgets Test Network PrintSupport)

find_package(LibAssuan ${LIBASSUAN_REQUIRED_VERSION} REQUIRED)
set_package_properties(LibAssuan PROPERTIES
  TYPE REQUIRED
  PURPOSE "Needed for Kleopatra to act as the GnuPG UI Server"
)
find_package(LibGpgError ${GPG_ERROR_REQUIRED_VERSION} REQUIRED)

set(kleopatra_release FALSE)

if(NOT kleopatra_release)
    find_package(Git)
    if(GIT_FOUND)
        execute_process(COMMAND ${GIT_EXECUTABLE} rev-parse
                        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
                        RESULT_VARIABLE rc
                        ERROR_QUIET)
        if(rc EQUAL 0)
            execute_process(COMMAND ${GIT_EXECUTABLE} log -1 --oneline --format=%h ${CMAKE_CURRENT_SOURCE_DIR}
                WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
                OUTPUT_VARIABLE Kleopatra_WC_REVISION)
            string(REGEX REPLACE "\n" "" Kleopatra_WC_REVISION "${Kleopatra_WC_REVISION}")

            execute_process(COMMAND ${GIT_EXECUTABLE} log -1 --oneline --format=%cI ${CMAKE_CURRENT_SOURCE_DIR}
                WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
                OUTPUT_VARIABLE Kleopatra_WC_LAST_CHANGED_DATE)
            string(REGEX REPLACE "^([0-9]+)-([0-9]+)-([0-9]+)T([0-9]+):([0-9]+):([0-9]+).*$" "\\1\\2\\3T\\4\\5\\6"
                   Kleopatra_WC_LAST_CHANGED_DATE "${Kleopatra_WC_LAST_CHANGED_DATE}")

            set(KLEOPATRA_VERSION_STRING "${KLEOPATRA_VERSION_STRING}+git${Kleopatra_WC_LAST_CHANGED_DATE}~${Kleopatra_WC_REVISION}")
        endif()
    endif()
endif()
if(EXISTS ${CMAKE_SOURCE_DIR}/VERSION)
    file(STRINGS ${CMAKE_SOURCE_DIR}/VERSION lines)
    list(GET lines 1 kleopatra_commit_id)
endif()

configure_file(${CMAKE_CURRENT_SOURCE_DIR}/version-kleopatra.h.in ${CMAKE_CURRENT_BINARY_DIR}/version-kleopatra.h)
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/config-kleopatra.h.in ${CMAKE_CURRENT_BINARY_DIR}/config-kleopatra.h)

include_directories(
    ${CMAKE_CURRENT_BINARY_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}
)

add_definitions(-DQT_NO_CONTEXTLESS_CONNECT)
ecm_set_disabled_deprecation_versions(QT 6.10.0 KF 6.21.0)

if(CMAKE_COMPILER_IS_GNUCXX)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wno-missing-braces -Wno-parentheses -Wno-ignored-qualifiers")
endif()
if(MINGW)
    # we do not care about different signedness of passed pointer arguments
    add_compile_options($<$<COMPILE_LANGUAGE:C>:-Wno-pointer-sign>)
endif()

add_definitions(-DQT_NO_EMIT)
remove_definitions(-DQT_NO_FOREACH)

# Disable the use of QStringBuilder for operator+ to prevent crashes when
# returning the result of concatenating string temporaries in lambdas. We do
# this for example in some std::transform expressions.
# This is a known issue: https://bugreports.qt.io/browse/QTBUG-47066
# Alternatively, one would always have to remember to force the lambdas to
# return a QString instead of QStringBuilder, but that's just too easy to
# forget and, unfortunately, the compiler doesn't issue a warning if one forgets
# this. So, it's just too dangerous.
# One can still use QStringBuilder explicitly with the operator% if necessary.
remove_definitions(-DQT_USE_FAST_OPERATOR_PLUS)
remove_definitions(-DQT_USE_QSTRINGBUILDER)

kde_enable_exceptions()
option(USE_UNITY_CMAKE_SUPPORT "Use UNITY cmake support (speedup compile time)" OFF)

set(COMPILE_WITH_UNITY_CMAKE_SUPPORT OFF)
if (USE_UNITY_CMAKE_SUPPORT)
    set(COMPILE_WITH_UNITY_CMAKE_SUPPORT ON)
endif()


add_subdirectory(src)

if(BUILD_TESTING)
    add_subdirectory(tests)
    add_subdirectory(autotests)
endif()

ecm_qt_install_logging_categories(
        EXPORT KLEOPATRA
        FILE kleopatra.categories
        DESTINATION ${KDE_INSTALL_LOGGINGCATEGORIESDIR}
        )

ki18n_install(po)
if(KF6DocTools_FOUND)
    kdoctools_install(po)
    add_subdirectory(doc)
endif()
ecm_feature_summary(WHAT ALL FATAL_ON_MISSING_REQUIRED_PACKAGES)

# add clang-format target for all our real source files
file(GLOB_RECURSE ALL_CLANG_FORMAT_SOURCE_FILES *.cpp *.h *.c)
kde_clang_format(${ALL_CLANG_FORMAT_SOURCE_FILES})
kde_configure_git_pre_commit_hook(CHECKS CLANG_FORMAT)

