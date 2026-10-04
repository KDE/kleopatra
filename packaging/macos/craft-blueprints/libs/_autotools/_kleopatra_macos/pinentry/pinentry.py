# SPDX-FileCopyrightText: Hannah von Reth <vonreth@kde.org> and others
# SPDX-License-Identifier: BSD-2-Clause

import info
from Package.AutoToolsPackageBase import AutoToolsPackageBase
from Utils import CraftHash


class subinfo(info.infoclass):
    def setTargets(self):
        for ver in ["1.3.2"]:
            self.targets[ver] = f"https://gnupg.org/ftp/gcrypt/pinentry/pinentry-{ver}.tar.bz2"
            self.targetInstSrc[ver] = f"pinentry-{ver}"

        self.targetDigests["1.3.2"] = (["8e986ed88561b4da6e9efe0c54fa4ca8923035c99264df0b0464497c5fb94e9e"], CraftHash.HashAlgorithm.SHA256)

        self.defaultTarget = "1.3.2"

    def setDependencies(self):
        self.buildDependencies["dev-utils/msys"] = None
        self.runtimeDependencies["virtual/base"] = None
        self.runtimeDependencies["libs/gpg-error"] = None
        self.runtimeDependencies["libs/assuan2"] = None
        self.runtimeDependencies["libs/qt/qtbase"] = None


class Package(AutoToolsPackageBase):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        # use the configure script of the release; autoreconf would also recreate the VERSION file
        self.subinfo.options.configure.autoreconf = False
        self.subinfo.options.configure.args += ["--enable-pinentry-qt", "--disable-pinentry-curses", "--disable-pinentry-tty", "--disable-fallback-curses"]
        # Qt 6 requires C++17, but the compiler's default standard may be older
        self.subinfo.options.configure.cxxflags += " -std=c++17"

    def unpack(self):
        if not super().unpack():
            return False
        # On case-insensitive file systems the VERSION file in the source directory shadows
        # the <version> header of the C++ standard library
        version = self.sourceDir() / "VERSION"
        if version.exists():
            version.rename(self.sourceDir() / "VERSION.txt")
        return True
