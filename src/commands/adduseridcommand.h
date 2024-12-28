/* -*- mode: c++; c-basic-offset:4 -*-
    commands/adduseridcommand.h

    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2008 Klarälvdalens Datakonsult AB
    SPDX-FileCopyrightText: 2022 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#pragma once

#include "command.h"

namespace Kleo
{
namespace Commands
{

class AddUserIDCommand : public Command
{
    Q_OBJECT
public:
    explicit AddUserIDCommand(QAbstractItemView *view, KeyListController *parent);
    explicit AddUserIDCommand(const GpgME::Key &key);
    ~AddUserIDCommand() override;

    /* reimp */ static Restrictions restrictions()
    {
        return OnlyOneKey | MustBeOpenPGP | NeedSecretKey;
    }

    void setName(const QString &name);
    const QString &name() const;

    void setEmail(const QString &email);
    const QString &email() const;

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
