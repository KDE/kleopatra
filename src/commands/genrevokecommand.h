/*
    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2017 Bundesamt für Sicherheit in der Informationstechnik
    SPDX-FileContributor: Intevation GmbH

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#pragma once

#include <commands/gnupgprocesscommand.h>

#include <QString>

class QWidget;

namespace Kleo
{
namespace Commands
{

class GenRevokeCommand : public GnuPGProcessCommand
{
    Q_OBJECT

public:
    explicit GenRevokeCommand(QAbstractItemView *view, KeyListController *parent);
    explicit GenRevokeCommand(KeyListController *parent);
    explicit GenRevokeCommand(const GpgME::Key &key);

    static Restrictions restrictions()
    {
        return OnlyOneKey | NeedSecretKey | MustBeOpenPGP;
    }

private:
    void postSuccessHook(QWidget *parentWidget) override;

    QStringList arguments() const override;
    QString errorCaption() const override;

    QString crashExitMessage(const QStringList &) const override;
    QString errorExitMessage(const QStringList &) const override;

    void doStart() override;

    QString mOutputFileName;
};

}
}
