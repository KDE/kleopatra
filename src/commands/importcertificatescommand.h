/* -*- mode: c++; c-basic-offset:4 -*-
    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2007, 2008 Klarälvdalens Datakonsult AB

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#pragma once

#include "command.h"

namespace Kleo
{

class ImportCertificatesCommand : public Command
{
    Q_OBJECT
public:
    explicit ImportCertificatesCommand(KeyListController *parent);
    explicit ImportCertificatesCommand(QAbstractItemView *view, KeyListController *parent);
    ~ImportCertificatesCommand() override;

protected:
    void doCancel() override;

protected:
    class Private;
    inline Private *d_func();
    inline const Private *d_func() const;

protected:
    explicit ImportCertificatesCommand(Private *pp);
    explicit ImportCertificatesCommand(QAbstractItemView *view, Private *pp);
};
}
