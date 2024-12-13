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
    mSignEncryptClipboardAction = new QAction(i18nc("@action", "Sign/Encrypt..."), this);
    const Kleo::Settings settings{};
    mDecryptVerifyClipboardAction = new QAction(i18nc("@action", "Decrypt/Verify..."), this);

    Q_SET_OBJECT_NAME(mClipboardMenu);
    Q_SET_OBJECT_NAME(mImportClipboardAction);
    Q_SET_OBJECT_NAME(mDecryptVerifyClipboardAction);

    connect(mImportClipboardAction, &QAction::triggered, this, &ClipboardMenu::slotImportClipboard);
    connect(mSignEncryptClipboardAction, &QAction::triggered, this, &ClipboardMenu::slotSignEncryptClipboard);
    connect(mDecryptVerifyClipboardAction, &QAction::triggered, this, &ClipboardMenu::slotDecryptVerifyClipboard);
    mClipboardMenu->addAction(mImportClipboardAction);
    mClipboardMenu->addAction(mSignEncryptClipboardAction);
    mClipboardMenu->addAction(mDecryptVerifyClipboardAction);
    connect(QApplication::clipboard(), &QClipboard::changed, this, &ClipboardMenu::slotEnableDisableActions);
    connect(KeyCache::instance().get(), &KeyCache::keyListingDone, this, &ClipboardMenu::slotEnableDisableActions);
    slotEnableDisableActions();
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

void ClipboardMenu::slotSignEncryptClipboard()
{
    startCommand(new SignEncryptClipboardCommand(nullptr));
}

void ClipboardMenu::slotDecryptVerifyClipboard()
{
    startCommand(new DecryptVerifyClipboardCommand(nullptr));
}

void ClipboardMenu::slotEnableDisableActions()
{
    const QSignalBlocker blocker(QApplication::clipboard());
    mImportClipboardAction->setEnabled(ImportCertificateFromClipboardCommand::canImportCurrentClipboard());
    // mEncryptClipboardAction->setEnabled(EncryptClipboardCommand::canEncryptCurrentClipboard());
    mDecryptVerifyClipboardAction->setEnabled(DecryptVerifyClipboardCommand::canDecryptVerifyCurrentClipboard());
}

#include "moc_clipboardmenu.cpp"
