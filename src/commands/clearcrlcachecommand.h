/* -*- mode: c++; c-basic-offset:4 -*-
    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2008 Klarälvdalens Datakonsult AB

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#pragma once

#include <commands/gnupgprocesscommand.h>

namespace Kleo
{
namespace Commands
{

class ClearCrlCacheCommand : public GnuPGProcessCommand
{
    Q_OBJECT
public:
    explicit ClearCrlCacheCommand(QAbstractItemView *view, KeyListController *parent);
    explicit ClearCrlCacheCommand(KeyListController *parent);
    ~ClearCrlCacheCommand() override;

private:
    QStringList arguments() const override;

    QString errorCaption() const override;
    QString successCaption() const override;

    QString crashExitMessage(const QStringList &) const override;
    QString errorExitMessage(const QStringList &) const override;
    QString successMessage(const QStringList &) const override;
};

}
}
