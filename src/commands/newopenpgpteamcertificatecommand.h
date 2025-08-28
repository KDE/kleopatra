// SPDX-FileCopyrightText: 2025 g10 Code GmbH
// SPDX-FileContributor: Tobias Fella <tobias.fella@gnupg.com>
// SPDX-License-Identifier: GPL-2.0-or-later

#pragma once

#include "newopenpgpcertificatecommand.h"

#include <QAbstractItemView>

namespace Kleo
{

class NewOpenPGPTeamCertificateCommand : public NewOpenPGPCertificateCommand
{
    Q_OBJECT
public:
    NewOpenPGPTeamCertificateCommand(QAbstractItemView *view, KeyListController *parent);
};

}
