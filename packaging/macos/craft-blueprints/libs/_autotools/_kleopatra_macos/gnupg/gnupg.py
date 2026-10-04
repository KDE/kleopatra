# SPDX-FileCopyrightText: Hannah von Reth <vonreth@kde.org> and others
# SPDX-License-Identifier: BSD-2-Clause

import info
from Package.AutoToolsPackageBase import AutoToolsPackageBase
from Utils import CraftHash


class subinfo(info.infoclass):
    def setTargets(self):
        # GnuPG 2.5 is needed on macOS because it can determine its own location there,
        # which makes it relocatable with gpgconf.ctl when bundled in the Kleopatra app
        for ver in ["2.5.24"]:
            self.targets[ver] = f"https://www.gnupg.org/ftp/gcrypt/gnupg/gnupg-{ver}.tar.bz2"
            self.targetInstSrc[ver] = f"gnupg-{ver}"

        self.targetDigests["2.5.24"] = (["bf149d01a2b9fcc0e4589b8ae8697d3d5c557ea48ed95a3fa55dd3b1187e6039"], CraftHash.HashAlgorithm.SHA256)

        self.defaultTarget = "2.5.24"

    def setDependencies(self):
        self.buildDependencies["dev-utils/msys"] = None
        self.runtimeDependencies["virtual/base"] = None
        self.runtimeDependencies["libs/gpg-error"] = None
        self.runtimeDependencies["libs/assuan2"] = None
        self.runtimeDependencies["libs/gcrypt"] = None
        self.runtimeDependencies["libs/npth"] = None
        self.runtimeDependencies["libs/libksba"] = None
        self.runtimeDependencies["libs/sqlite"] = None
        self.runtimeDependencies["libs/ntbtls"] = None
        # gpg-agent needs a pinentry for asking for passphrases
        self.runtimeDependencies["libs/pinentry"] = None


class Package(AutoToolsPackageBase):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.subinfo.options.configure.autoreconf = False
        self.subinfo.options.configure.args += ["--disable-doc", "--disable-ldap"]
        self.subinfo.options.configure.cflags += " -Wno-error=int-conversion"
