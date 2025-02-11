/*
    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2017 Bundesamt für Sicherheit in der Informationstechnik
    SPDX-FileContributor: Intevation GmbH

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#pragma once

#include <commands/gnupgprocesscommand.h>

#include <QString>
#include <QTemporaryDir>

class QWidget;

namespace GpgME
{
class Error;
class Key;
} // namespace GpgME

namespace Kleo
{
namespace Commands
{

class ImportPaperKeyCommand : public GnuPGProcessCommand
{
    Q_OBJECT

public:
    explicit ImportPaperKeyCommand(const GpgME::Key &key);

    static Restrictions restrictions()
    {
        return OnlyOneKey | MustBeOpenPGP;
    }

    void postSuccessHook(QWidget *parentWidget) override;

    QString successMessage(const QStringList &args) const override;

private Q_SLOTS:
    void exportResult(const GpgME::Error &err, const QByteArray &data);

private:
    QStringList arguments() const override;

    void doStart() override;

    QString errorCaption() const override;

    QString crashExitMessage(const QStringList &) const override;
    QString errorExitMessage(const QStringList &) const override;

    QTemporaryDir mTmpDir;
    QString mFileName;
};

}
}
