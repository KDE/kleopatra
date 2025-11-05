// SPDX-FileCopyrightText: 2025 g10 Code GmbH
// SPDX-FileContributor: Tobias Fella <tobias.fella@gnupg.com>
// SPDX-License-Identifier: LGPL-2.0-or-later

#pragma once

#include "command.h"

namespace Kleo
{
namespace Commands
{

class ExportSecretTeamKeyCommand : public Command
{
    Q_OBJECT
public:
    explicit ExportSecretTeamKeyCommand(QAbstractItemView *view, KeyListController *parent);
    explicit ExportSecretTeamKeyCommand(const GpgME::Key &key);
    ~ExportSecretTeamKeyCommand() override;

    /* reimp */ static Restrictions restrictions()
    {
        return OnlyOneKey | NeedSecretKey /* We only want the owner to export the key */ | MustBeOpenPGP | NeedSecretEncryptSubkey;
    }

private:
    void doStart() override;
    void doCancel() override;

private:
    class Private;
    inline Private *d_func();
    inline const Private *d_func() const;
};

}
}
