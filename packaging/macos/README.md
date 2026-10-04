<!--
SPDX-FileCopyrightText: none
SPDX-License-Identifier: CC0-1.0
-->

# Building Kleopatra for macOS

Kleopatra is built and packaged for macOS with [KDE Craft](https://community.kde.org/Craft).

## Craft blueprint overlay

`craft-blueprints/` contains blueprints that replace some of the blueprints of
craft-blueprints-kde on macOS:

- GnuPG 2.5, which can determine its own location on macOS and can therefore be
  relocated with `gpgconf.ctl` when it is bundled in the app bundle
- libgcrypt and libassuan versions required by GnuPG 2.5
- pinentry-qt, which is bundled for asking for passphrases

Register the overlay in `<CraftRoot>/etc/CraftSettings.ini`:

```ini
[Blueprints]
Locations = /path/to/kleopatra/packaging/macos/craft-blueprints
```

## Building and packaging

```sh
source <CraftRoot>/craft/craftenv.sh
craft --set version=master kde/pim
craft --set srcDir=/path/to/kleopatra kde/pim/kleopatra
craft kde/pim/kleopatra
craft --package kde/pim/kleopatra
```

The package is a disk image in `<CraftRoot>/tmp/`. The app bundle contains GnuPG and
uses it instead of a GnuPG installed on the system. The app in
`<CraftRoot>/Applications/KDE/` (without packaging) uses the GnuPG found in `PATH`.
