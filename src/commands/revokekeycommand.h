/* -*- mode: c++; c-basic-offset:4 -*-
    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2022 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#pragma once

#include "command.h"

namespace GpgME
{
class Key;
}

namespace Kleo
{
class RevokeKeyCommand : public Command
{
    Q_OBJECT
public:
    RevokeKeyCommand(QAbstractItemView *view, KeyListController *parent);
    explicit RevokeKeyCommand(const GpgME::Key &key);
    ~RevokeKeyCommand() override;

    static Restrictions restrictions()
    {
        return OnlyOneKey | NeedSecretKey | MustBeOpenPGP;
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
