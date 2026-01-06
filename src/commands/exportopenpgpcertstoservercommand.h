/* -*- mode: c++; c-basic-offset:4 -*-
    commands/exportopenpgpcertstoservercommand.h

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

class ExportOpenPGPCertsToServerCommand : public GnuPGProcessCommand
{
    Q_OBJECT
public:
    ExportOpenPGPCertsToServerCommand(QAbstractItemView *view, KeyListController *parent);
    explicit ExportOpenPGPCertsToServerCommand(KeyListController *parent);
    explicit ExportOpenPGPCertsToServerCommand(const GpgME::Key &key);
    explicit ExportOpenPGPCertsToServerCommand(const std::vector<GpgME::Key> &keys);

    ~ExportOpenPGPCertsToServerCommand() override;

    static Restrictions restrictions();

private:
    bool preStartHook(QWidget *) const override;

    QStringList arguments() const override;

    QString errorCaption() const override;
    QString successCaption() const override;

    QString crashExitMessage(const QStringList &) const override;
    QString errorExitMessage(const QStringList &) const override;
    QString successMessage(const QStringList &) const override;
};

}
}
