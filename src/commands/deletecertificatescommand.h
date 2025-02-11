/* -*- mode: c++; c-basic-offset:4 -*-
    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2007 Klarälvdalens Datakonsult AB

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#pragma once

#include "command.h"

namespace Kleo
{
class DeleteCertificatesCommand : public Command
{
    Q_OBJECT
public:
    explicit DeleteCertificatesCommand(QAbstractItemView *view, KeyListController *parent);
    explicit DeleteCertificatesCommand(KeyListController *parent);
    ~DeleteCertificatesCommand() override;

    /* reimp */ static Restrictions restrictions()
    {
        return NeedSelection;
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
