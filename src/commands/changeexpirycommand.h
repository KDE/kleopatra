/*
    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2008 Klarälvdalens Datakonsult AB

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#pragma once

#include <commands/command.h>

namespace GpgME
{
class Subkey;
}

namespace Kleo
{
namespace Commands
{

class ChangeExpiryCommand : public Command
{
    Q_OBJECT
public:
    explicit ChangeExpiryCommand(QAbstractItemView *view, KeyListController *parent);
    explicit ChangeExpiryCommand(KeyListController *parent);
    explicit ChangeExpiryCommand(const GpgME::Key &key);
    ~ChangeExpiryCommand() override;

    /* reimp */ static Restrictions restrictions()
    {
        return OnlyOneKey | MustBeOpenPGP | NeedSecretKey;
    }

    void setSubkey(const GpgME::Subkey &subkey);

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
