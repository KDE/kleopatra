/*
    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2016 Bundesamt für Sicherheit in der Informationstechnik
    SPDX-FileContributor: Intevation GmbH

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include <config-kleopatra.h>

#include "signencryptfoldercommand.h"

#include <KLocalizedString>

#include <QApplication>
#include <QFileDialog>

using namespace Kleo;
using namespace Kleo::Commands;

SignEncryptFolderCommand::SignEncryptFolderCommand(QAbstractItemView *v, KeyListController *c)
    : SignEncryptFilesCommand(v, c)
{
    setArchivePolicy(Force);
}

SignEncryptFolderCommand::SignEncryptFolderCommand(KeyListController *c)
    : SignEncryptFolderCommand(nullptr, c)
{
}

QStringList SignEncryptFolderCommand::selectFiles() const
{
    const QString dir = QFileDialog::getExistingDirectory(qApp->activeWindow(), i18n("Select Folder to Sign and/or Encrypt"));
    if (dir.isNull()) {
        return QStringList();
    }
    return QStringList() << dir;
}

#include "moc_signencryptfoldercommand.cpp"
