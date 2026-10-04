# SPDX-FileCopyrightText: none
# SPDX-License-Identifier: CC0-1.0
#
# Relocates the GnuPG installation bundled in the Kleopatra app bundle. GnuPG requires
# absolute paths here, so Kleopatra sets KLEOPATRA_GNUPG_ROOTDIR to the Contents directory
# of the app bundle before it starts any GnuPG program.
rootdir = ${KLEOPATRA_GNUPG_ROOTDIR}
sysconfdir = /etc/gnupg
