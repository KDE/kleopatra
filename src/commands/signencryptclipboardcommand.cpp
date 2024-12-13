/*
    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2008 Klarälvdalens Datakonsult AB
    SPDX-FileCopyrightText: 2025 g10 Code GmbH
    SPDX-FileContributor: Tobias Fella <tobias.fella@gnupg.com>

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include <config-kleopatra.h>

#include "signencryptclipboardcommand.h"

#ifndef QT_NO_CLIPBOARD

#include "dialogs/signencryptclipboarddialog.h"

#include "command_p.h"

#include "kleopatra_debug.h"
#include <KLocalizedString>

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
    explicit Private(SignEncryptClipboardCommand *qq);
    ~Private() override;

    void slotDialogRejected();
    void slotDialogAccepted();

private:
    QPointer<SignEncryptClipboardDialog> dialog;
    SignEncryptClipboardCommand::Mode mode = SignEncryptClipboardCommand::Mode::SignEncrypt;
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

SignEncryptClipboardCommand::Private::Private(SignEncryptClipboardCommand *qq)
    : Command::Private(qq)
{
}

SignEncryptClipboardCommand::Private::~Private()
{
    qCDebug(KLEOPATRA_LOG);
    delete dialog;
}

void SignEncryptClipboardCommand::Private::slotDialogRejected()
{
    canceled();
}

void SignEncryptClipboardCommand::Private::slotDialogAccepted()
{
    finished();
}

SignEncryptClipboardCommand::SignEncryptClipboardCommand(Mode mode)
    : Command(new Private(this))
{
    d->mode = mode;
}

void SignEncryptClipboardCommand::doStart()
{
    d->dialog = new SignEncryptClipboardDialog(d->mode);
    d->dialog->show();
    connect(d->dialog.get(), &QDialog::rejected, this, [this]() {
        d->slotDialogRejected();
    });

    connect(d->dialog.get(), &QDialog::accepted, this, [this]() {
        d->slotDialogAccepted();
    });
}

void SignEncryptClipboardCommand::doCancel()
{
    qCDebug(KLEOPATRA_LOG);
}

#undef d
#undef q

#include "moc_signencryptclipboardcommand.cpp"

#endif // QT_NO_CLIPBOARD
