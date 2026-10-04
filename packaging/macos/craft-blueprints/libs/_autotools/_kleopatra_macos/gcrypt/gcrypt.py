# SPDX-FileCopyrightText: Hannah von Reth <vonreth@kde.org> and others
# SPDX-License-Identifier: BSD-2-Clause

import info
from Package.AutoToolsPackageBase import AutoToolsPackageBase
from Utils import CraftHash


class subinfo(info.infoclass):
    def setTargets(self):
        for ver in ["1.12.4"]:
            self.targets[ver] = f"https://gnupg.org/ftp/gcrypt/libgcrypt/libgcrypt-{ver}.tar.bz2"
            self.targetInstSrc[ver] = f"libgcrypt-{ver}"
        self.targetDigests["1.12.4"] = (["d77f68f48879510e79a2f65977ccc68981781ea0923e5bdffac2a193ea3d660e"], CraftHash.HashAlgorithm.SHA256)

        self.description = " General purpose crypto library based on the code used in GnuPG."
        self.defaultTarget = "1.12.4"

    def setDependencies(self):
        self.buildDependencies["dev-utils/msys"] = None
        self.runtimeDependencies["virtual/base"] = None
        self.runtimeDependencies["libs/gpg-error"] = None


class Package(AutoToolsPackageBase):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.subinfo.options.configure.args += ["--disable-asm", "--disable-padlock-support"]
