# SPDX-FileCopyrightText: none
# SPDX-License-Identifier: BSD-3-Clause
set(EXECUTABLE_OUTPUT_PATH ${CMAKE_CURRENT_BINARY_DIR})

set(kleoclient_TESTS
  test_signencryptfilescommand
  test_decryptverifyfilescommand
)

foreach(_kleoclient_test ${kleoclient_TESTS})
  add_executable( ${_kleoclient_test} ${_kleoclient_test}.cpp )
  ecm_mark_as_test(${_kleoclient_test})

  target_link_libraries("${_kleoclient_test}"
    kleopatraclientcore
    Qt::Gui
    Qt::Core
)
endforeach()
