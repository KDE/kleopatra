/*
    SPDX-FileCopyrightText: 2024 g10 Code GmbH
    SPDX-FileContributor: Tobias Fella <tobias.fella@gnupg.com>

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#pragma once

#include <commands/command.h>

namespace Kleo
{
namespace Commands
{

class ToggleCertificateEnabledCommand : public Command
{
    Q_OBJECT
public:
    ToggleCertificateEnabledCommand(QAbstractItemView *view, KeyListController *parent);
    ~ToggleCertificateEnabledCommand() override;

    static Restrictions restrictions()
    {
        return OnlyOneKey | MustBeOpenPGP;
    }

    static bool isSupported();

private:
    void doStart() override;
    void doCancel() override;

    class Private;
    inline Private *d_func();
    inline const Private *d_func() const;
};

}
}
