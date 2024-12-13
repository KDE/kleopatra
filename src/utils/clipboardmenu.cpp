/*
  SPDX-FileCopyrightText: 2014-2021 Laurent Montel <montel@kde.org>

  SPDX-License-Identifier: GPL-2.0-only
*/

#include <config-kleopatra.h>

#include "clipboardmenu.h"

#include "kdtoolsglobal.h"
#include "mainwindow.h"

#include <settings.h>

#include <commands/decryptverifyclipboardcommand.h>
#include <commands/importcertificatefromclipboardcommand.h>
#include <commands/signencryptclipboardcommand.h>

#include <Libkleo/Algorithm>
#include <Libkleo/Compat>
#include <Libkleo/KeyCache>

#include <KActionMenu>
#include <KLocalizedString>

#include <QAction>
#include <QApplication>
#include <QClipboard>
#include <QSignalBlocker>

#include <gpgme++/key.h>

using namespace Kleo;

using namespace Kleo::Commands;

ClipboardMenu::ClipboardMenu(QObject *parent)
    : QObject{parent}
{
    mClipboardMenu = new KActionMenu(i18n("Clipboard"), this);
    mImportClipboardAction = new QAction(i18nc("@action", "Certificate Import"), this);
    mEncryptClipboardAction = new QAction(i18nc("@action", "Encrypt..."), this);
    mSignEncryptClipboardAction = new QAction(i18nc("@action", "Sign/Encrypt..."), this);
    mSignClipboardAction = new QAction(i18nc("@action", "Sign..."), this);
    mDecryptVerifyClipboardAction = new QAction(i18nc("@action", "Decrypt/Verify..."), this);

    Q_SET_OBJECT_NAME(mClipboardMenu);
    Q_SET_OBJECT_NAME(mImportClipboardAction);
    Q_SET_OBJECT_NAME(mEncryptClipboardAction);
    Q_SET_OBJECT_NAME(mSignClipboardAction);
    Q_SET_OBJECT_NAME(mSignEncryptClipboardAction);
    Q_SET_OBJECT_NAME(mDecryptVerifyClipboardAction);

    connect(mImportClipboardAction, &QAction::triggered, this, &ClipboardMenu::slotImportClipboard);
    connect(mEncryptClipboardAction, &QAction::triggered, this, &ClipboardMenu::slotEncryptClipboard);
    connect(mSignClipboardAction, &QAction::triggered, this, &ClipboardMenu::slotSignClipboard);
    connect(mSignEncryptClipboardAction, &QAction::triggered, this, &ClipboardMenu::slotSignEncryptClipboard);
    connect(mDecryptVerifyClipboardAction, &QAction::triggered, this, &ClipboardMenu::slotDecryptVerifyClipboard);
    mClipboardMenu->addAction(mImportClipboardAction);
    mClipboardMenu->addAction(mEncryptClipboardAction);
    mClipboardMenu->addAction(mSignClipboardAction);
    mClipboardMenu->addAction(mSignEncryptClipboardAction);
    mClipboardMenu->addAction(mDecryptVerifyClipboardAction);
}

ClipboardMenu::~ClipboardMenu() = default;

void ClipboardMenu::setMainWindow(MainWindow *window)
{
    mWindow = window;
}

KActionMenu *ClipboardMenu::clipboardMenu() const
{
    return mClipboardMenu;
}

void ClipboardMenu::startCommand(Command *cmd)
{
    Q_ASSERT(cmd);
    cmd->setParent(mWindow);
    cmd->start();
}

void ClipboardMenu::slotImportClipboard()
{
    startCommand(new ImportCertificateFromClipboardCommand(nullptr));
}

void ClipboardMenu::slotEncryptClipboard()
{
    startCommand(new SignEncryptClipboardCommand(SignEncryptClipboardCommand::Mode::Encrypt));
}

void ClipboardMenu::slotSignClipboard()
{
    startCommand(new SignEncryptClipboardCommand(SignEncryptClipboardCommand::Mode::Sign));
}

void ClipboardMenu::slotSignEncryptClipboard()
{
    startCommand(new SignEncryptClipboardCommand(SignEncryptClipboardCommand::Mode::SignEncrypt));
}

void ClipboardMenu::slotDecryptVerifyClipboard()
{
    startCommand(new DecryptVerifyClipboardCommand(nullptr));
}

#include "moc_clipboardmenu.cpp"
