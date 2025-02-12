/*
    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2010 Klarälvdalens Datakonsult AB

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#pragma once

#include <commands/command.h>

namespace Kleo
{
namespace Commands
{

class ChangePassphraseCommand : public Command
{
    Q_OBJECT
public:
    explicit ChangePassphraseCommand(QAbstractItemView *view, KeyListController *parent);
    explicit ChangePassphraseCommand(KeyListController *parent);
    explicit ChangePassphraseCommand(const GpgME::Key &key);
    ~ChangePassphraseCommand() override;

    /* reimp */ static Restrictions restrictions()
    {
        return OnlyOneKey | NeedSecretSubkeyData;
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
