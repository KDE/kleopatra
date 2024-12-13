/* -*- mode: c++; c-basic-offset:4 -*-
    commands/signclipboardcommand.cpp

    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2008 Klarälvdalens Datakonsult AB

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include <config-kleopatra.h>

#include "dialogs/signencryptclipboarddialog.h"
#include "signencryptclipboardcommand.h"

#ifndef QT_NO_CLIPBOARD

#include "command_p.h"

#include <crypto/signemailcontroller.h>

#include <utils/input.h>
#include <utils/output.h>

#include <Libkleo/Stl_Util>

#include "kleopatra_debug.h"
#include <KLocalizedString>

#include <QApplication>
#include <QClipboard>
#include <QMimeData>

#include <exception>

using namespace Kleo;
using namespace Kleo::Commands;
using namespace Kleo::Crypto;

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

private:
    void slotSignersResolved();
    void slotControllerDone()
    {
        finished();
    }
    void slotControllerError(int, const QString &)
    {
        finished();
    }

private:
    std::shared_ptr<const ExecutionContext> shared_qq;
    std::shared_ptr<Input> input;
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
    , shared_qq(qq, [](SignEncryptClipboardCommand *) { })
    , input()
{
}

SignEncryptClipboardCommand::Private::~Private()
{
    qCDebug(KLEOPATRA_LOG);
}

SignEncryptClipboardCommand::SignEncryptClipboardCommand(KeyListController *c)
    : Command(new Private(this, c))
{
    d->init();
    // d->controller.setProtocol(protocol);
}

SignEncryptClipboardCommand::SignEncryptClipboardCommand(QAbstractItemView *v, KeyListController *c)
    : Command(v, new Private(this, c))
{
    d->init();
    // d->controller.setProtocol(protocol);
}

void SignEncryptClipboardCommand::Private::init()
{
}

SignEncryptClipboardCommand::~SignEncryptClipboardCommand()
{
    qCDebug(KLEOPATRA_LOG);
}

void SignEncryptClipboardCommand::doStart()
{
    try {
        // snapshot clipboard content here, in case it's being changed...
        // d->input = Input::createFromClipboard();

        auto dialog = new SignEncryptClipboardDialog;
        dialog->show();

        // connect(&d->controller, &SignEMailController::signersResolved, this, [this]() {
        //     d->slotSignersResolved();
        // });
        //
        // d->controller.startResolveSigners();

    } catch (const std::exception &e) {
        d->information(i18n("An error occurred: %1", QString::fromLocal8Bit(e.what())), i18n("Sign Clipboard Error"));
        d->finished();
    }
}

void SignEncryptClipboardCommand::Private::slotSignersResolved()
{
    // try {
    //     controller.setInputAndOutput(input, Output::createFromClipboard());
    //     input.reset(); // no longer needed, so don't keep a reference
    //     controller.start();
    // } catch (const std::exception &e) {
    //     information(i18n("An error occurred: %1", QString::fromLocal8Bit(e.what())), i18n("Sign Clipboard Error"));
    //     finished();
    // }
}

void SignEncryptClipboardCommand::doCancel()
{
    qCDebug(KLEOPATRA_LOG);
    // d->controller.cancel();
}

#undef d
#undef q

#include "moc_signencryptclipboardcommand.cpp"

#endif // QT_NO_CLIPBOARD
