/* -*- mode: c++; c-basic-offset:4 -*-
    commands/signclipboardcommand.cpp

    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2008 Klarälvdalens Datakonsult AB

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include <config-kleopatra.h>

#include "signencryptclipboardcommand.h"

#ifndef QT_NO_CLIPBOARD

#include "dialogs/signencryptclipboarddialog.h"

#include "command_p.h"

#include "kleopatra_debug.h"
#include <KLocalizedString>

#include <exception>

#include <QApplication>
#include <QClipboard>
#include <QMimeData>

using namespace Kleo;
using namespace Kleo::Commands;

class SignEncryptClipboardCommand::Private : public Command::Private
{
    friend class ::Kleo::Commands::SignEncryptClipboardCommand;
    SignEncryptClipboardCommand *q_func() const
    {
        return static_cast<SignEncryptClipboardCommand *>(q);
    }

public:
    explicit Private(SignEncryptClipboardCommand *qq, KeyListController *c);
    ~Private() override;

    void init();
    void slotDialogRejected();

private:
    std::unique_ptr<SignEncryptClipboardDialog> dialog;
};

SignEncryptClipboardCommand::Private *SignEncryptClipboardCommand::d_func()
{
    return static_cast<Private *>(d.get());
}
const SignEncryptClipboardCommand::Private *SignEncryptClipboardCommand::d_func() const
{
    return static_cast<const Private *>(d.get());
}

#define d d_func()
#define q q_func()

SignEncryptClipboardCommand::Private::Private(SignEncryptClipboardCommand *qq, KeyListController *c)
    : Command::Private(qq, c)
{
}

SignEncryptClipboardCommand::Private::~Private()
{
    qCDebug(KLEOPATRA_LOG);
}

void SignEncryptClipboardCommand::Private::slotDialogRejected()
{
    canceled();
}

SignEncryptClipboardCommand::SignEncryptClipboardCommand(KeyListController *c)
    : Command(new Private(this, c))
{
}

SignEncryptClipboardCommand::~SignEncryptClipboardCommand()
{
    qCDebug(KLEOPATRA_LOG);
}

void SignEncryptClipboardCommand::doStart()
{
    try {
        d->dialog = std::make_unique<SignEncryptClipboardDialog>();
    } catch (const std::exception &e) {
        d->information(i18n("An error occurred: %1", QString::fromLocal8Bit(e.what())), i18n("Sign Clipboard Error"));
        d->finished();
    }
    d->dialog->show();
    connect(d->dialog.get(), &QDialog::rejected, this, [this]() {
        d->slotDialogRejected();
    });
}

void SignEncryptClipboardCommand::doCancel()
{
    qCDebug(KLEOPATRA_LOG);
    d->dialog->deleteLater();
}

bool SignEncryptClipboardCommand::canSignEncryptCurrentClipboard()
{
    if (const auto &clip = QApplication::clipboard()) {
        if (const auto &mime = clip->mimeData()) {
            return mime->hasText();
        }
    }
    return false;
}

#undef d
#undef q

#include "moc_signencryptclipboardcommand.cpp"

#endif // QT_NO_CLIPBOARD
