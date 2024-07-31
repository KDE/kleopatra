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
#include <commands/encryptclipboardcommand.h>
#include <commands/importcertificatefromclipboardcommand.h>
#include <commands/signclipboardcommand.h>

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
    mImportClipboardAction = new QAction(i18n("Certificate Import"), this);
    mEncryptClipboardAction = new QAction(i18n("Encrypt..."), this);
    const Kleo::Settings settings{};
    if (settings.cmsEnabled() && settings.cmsSigningAllowed()) {
        mSmimeSignClipboardAction = new QAction(i18n("S/MIME-Sign..."), this);
        Q_SET_OBJECT_NAME(mSmimeSignClipboardAction);
    }
    mOpenPGPSignClipboardAction = new QAction(i18n("OpenPGP-Sign..."), this);
    mDecryptVerifyClipboardAction = new QAction(i18n("Decrypt/Verify..."), this);

    Q_SET_OBJECT_NAME(mClipboardMenu);
    Q_SET_OBJECT_NAME(mImportClipboardAction);
    Q_SET_OBJECT_NAME(mEncryptClipboardAction);
    Q_SET_OBJECT_NAME(mOpenPGPSignClipboardAction);
    Q_SET_OBJECT_NAME(mDecryptVerifyClipboardAction);

    connect(mImportClipboardAction, &QAction::triggered, this, &ClipboardMenu::slotImportClipboard);
    connect(mEncryptClipboardAction, &QAction::triggered, this, &ClipboardMenu::slotEncryptClipboard);
    if (mSmimeSignClipboardAction) {
        connect(mSmimeSignClipboardAction, &QAction::triggered, this, &ClipboardMenu::slotSMIMESignClipboard);
    }
    connect(mOpenPGPSignClipboardAction, &QAction::triggered, this, &ClipboardMenu::slotOpenPGPSignClipboard);
    connect(mDecryptVerifyClipboardAction, &QAction::triggered, this, &ClipboardMenu::slotDecryptVerifyClipboard);
    mClipboardMenu->addAction(mImportClipboardAction);
    mClipboardMenu->addAction(mEncryptClipboardAction);
    if (mSmimeSignClipboardAction) {
        mClipboardMenu->addAction(mSmimeSignClipboardAction);
    }
    mClipboardMenu->addAction(mOpenPGPSignClipboardAction);
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

void ClipboardMenu::slotEncryptClipboard()
{
    startCommand(new EncryptClipboardCommand(nullptr));
}

void ClipboardMenu::slotOpenPGPSignClipboard()
{
    startCommand(new SignClipboardCommand(GpgME::OpenPGP, nullptr));
}

void ClipboardMenu::slotSMIMESignClipboard()
{
    startCommand(new SignClipboardCommand(GpgME::CMS, nullptr));
}

void ClipboardMenu::slotDecryptVerifyClipboard()
{
    startCommand(new DecryptVerifyClipboardCommand(nullptr));
}

namespace
{

bool hasSigningKeys(GpgME::Protocol protocol)
{
    if (!KeyCache::instance()->initialized()) {
        return false;
    }
    return std::ranges::any_of(KeyCache::instance()->keys(), [protocol](const auto &k) {
        return k.hasSecret() && Kleo::keyHasSign(k) && (k.protocol() == protocol);
    });
}

}

void ClipboardMenu::slotEnableDisableActions()
{
    const QSignalBlocker blocker(QApplication::clipboard());
    mImportClipboardAction->setEnabled(ImportCertificateFromClipboardCommand::canImportCurrentClipboard());
    mEncryptClipboardAction->setEnabled(EncryptClipboardCommand::canEncryptCurrentClipboard());
    mOpenPGPSignClipboardAction->setEnabled(SignClipboardCommand::canSignCurrentClipboard() && hasSigningKeys(GpgME::OpenPGP));
    if (mSmimeSignClipboardAction) {
        mSmimeSignClipboardAction->setEnabled(SignClipboardCommand::canSignCurrentClipboard() && hasSigningKeys(GpgME::CMS));
    }
    mDecryptVerifyClipboardAction->setEnabled(DecryptVerifyClipboardCommand::canDecryptVerifyCurrentClipboard());
}
