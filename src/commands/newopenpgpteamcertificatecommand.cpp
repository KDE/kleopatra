// SPDX-FileCopyrightText: 2025 g10 Code GmbH
// SPDX-FileContributor: Tobias Fella <tobias.fella@gnupg.com>
// SPDX-License-Identifier: GPL-2.0-or-later

#include "newopenpgpteamcertificatecommand.h"

using namespace Kleo;
using namespace GpgME;

NewOpenPGPTeamCertificateCommand::NewOpenPGPTeamCertificateCommand(QAbstractItemView *v, KeyListController *c)
    : NewOpenPGPCertificateCommand(v, c)
{
    setIsTeamKey(true);
}

#include "moc_newopenpgpteamcertificatecommand.cpp"
