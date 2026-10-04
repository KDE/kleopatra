# SPDX-FileCopyrightText: none
# SPDX-License-Identifier: BSD-3-Clause

# Directory layout inside the app bundle for using a bundled GnuPG.
#
# The packaging puts the programs of GnuPG into Contents/MacOS and its data into
# Contents/Resources. GnuPG expects its programs in <rootdir>/bin and <rootdir>/libexec and
# its data in <rootdir>/share/gnupg, and it looks for gpgconf.ctl in <dir of gpgconf>/../bin.
# Therefore, Contents/bin contains gpgconf.ctl and symlinks to the GnuPG programs, and
# Contents/libexec and Contents/share are symlinks to Contents/MacOS and Contents/Resources.
# The symlinks dangle until the packaging adds GnuPG to the bundle, so that a build without
# a bundled GnuPG keeps using the GnuPG installed on the system.

set(_gnupg_programs
    dirmngr
    dirmngr-client
    gpg
    gpg-agent
    gpg-card
    gpg-connect-agent
    gpg-wks-client
    gpgconf
    gpgsm
    gpgtar
    gpgv
    pinentry
)

set(_layout_dir "${CMAKE_CURRENT_BINARY_DIR}/bundle-gnupg-layout")
file(REMOVE_RECURSE "${_layout_dir}")
file(MAKE_DIRECTORY "${_layout_dir}/bin")
foreach(_program ${_gnupg_programs})
    file(CREATE_LINK "../MacOS/${_program}" "${_layout_dir}/bin/${_program}" SYMBOLIC)
endforeach()
file(CREATE_LINK "MacOS" "${_layout_dir}/libexec" SYMBOLIC)
file(CREATE_LINK "Resources" "${_layout_dir}/share" SYMBOLIC)
configure_file(gpgconf.ctl "${_layout_dir}/bin/gpgconf.ctl" COPYONLY)

install(DIRECTORY "${_layout_dir}/" DESTINATION "${KDE_INSTALL_BUNDLEDIR}/kleopatra.app/Contents")
