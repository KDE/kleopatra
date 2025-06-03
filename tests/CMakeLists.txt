# SPDX-FileCopyrightText: none
# SPDX-License-Identifier: BSD-3-Clause
add_subdirectory(gnupg_home)

set(EXECUTABLE_OUTPUT_PATH ${CMAKE_CURRENT_BINARY_DIR})
include_directories(
  ${CMAKE_SOURCE_DIR}/src/
  ${CMAKE_BINARY_DIR}/src/
  ${GPGME_INCLUDES}
)

########### next target ###############

set(test_verify_SRCS test_verify.cpp)

add_definitions(-DKLEO_TEST_GNUPGHOME="${CMAKE_CURRENT_BINARY_DIR}/gnupg_home")
add_definitions(-DKLEO_TEST_DATADIR="${CMAKE_CURRENT_SOURCE_DIR}")


add_executable(test_verify  ${test_verify_SRCS})
add_test(NAME test_verify COMMAND test_verify)
ecm_mark_as_test(test_verify)

target_link_libraries(test_verify
  KPim6::Libkleo
  Qt::Test
  KF6::CoreAddons
  KF6::I18n
  Qt::Widgets
)

target_link_libraries(test_verify QGpgmeQt6)

########### next target ###############

  # this doesn't yet work on Windows

  add_definitions(-DGPG_ERR_SOURCE_DEFAULT=GPG_ERR_SOURCE_USER_2)

  set(test_uiserver_SRCS test_uiserver.cpp ${CMAKE_SOURCE_DIR}/src/utils/wsastarter.cpp)

  add_executable(test_uiserver ${test_uiserver_SRCS})

  target_link_libraries(test_uiserver KF6::I18n KPim6::Libkleo LibAssuan::LibAssuan LibGpgError::LibGpgError)

  target_link_libraries(test_uiserver QGpgmeQt6)

