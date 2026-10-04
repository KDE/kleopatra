# SPDX-FileCopyrightText: Hannah von Reth <vonreth@kde.org> and others
# SPDX-License-Identifier: BSD-2-Clause

import info
from CraftCore import CraftCore
from CraftOS.osutils import OsUtils
from Package.AutoToolsPackageBase import AutoToolsPackageBase
from Utils import CraftHash


class subinfo(info.infoclass):
    def setTargets(self):
        # 3.0.2 fixes a typo in assuan.h that breaks building GnuPG 2.5
        for ver in ["3.0.2"]:
            self.targets[ver] = f"https://www.gnupg.org/ftp/gcrypt/libassuan/libassuan-{ver}.tar.bz2"
            self.targetInstSrc[ver] = f"libassuan-{ver}"

        self.targetDigests["3.0.2"] = (["d2931cdad266e633510f9970e1a2f346055e351bb19f9b78912475b8074c36f6"], CraftHash.HashAlgorithm.SHA256)

        self.description = "An IPC library used by some of the other GnuPG related packages"
        self.defaultTarget = "3.0.2"

    def setDependencies(self):
        self.buildDependencies["dev-utils/msys"] = None
        self.runtimeDependencies["virtual/base"] = None
        self.runtimeDependencies["libs/gpg-error"] = None


class Package(AutoToolsPackageBase):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)

    def postInstall(self):
        return self.patchInstallPrefix(
            [self.installDir() / "bin/libassuan-config"],
            OsUtils.toMSysPath(self.subinfo.buildPrefix),
            OsUtils.toMSysPath(CraftCore.standardDirs.craftRoot()),
        )
