/* -*- mode: c++; c-basic-offset:4 -*-
    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2007 Klarälvdalens Datakonsult AB

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#pragma once

#include <commands/command.h>

namespace GpgME
{
class Key;
}

namespace Kleo
{
namespace Commands
{

class DetailsCommand : public Command
{
    Q_OBJECT
public:
    DetailsCommand(QAbstractItemView *view, KeyListController *parent);
    explicit DetailsCommand(const GpgME::Key &key);
    ~DetailsCommand() override;

    /* reimp */ static Restrictions restrictions()
    {
        return OnlyOneKey;
    }

private:
    void doStart() override;
    void doCancel() override;

private:
    class Private;
    inline Private *d_func();
    inline const Private *d_func() const;
    Q_PRIVATE_SLOT(d_func(), void slotDialogClosed())
};

}
}
