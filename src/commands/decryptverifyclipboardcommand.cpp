/* -*- mode: c++; c-basic-offset:4 -*-
    commands/decryptverifyclipboardcommand.cpp

    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2008 Klarälvdalens Datakonsult AB

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include <config-kleopatra.h>

#include "decryptverifyclipboardcommand.h"

#ifndef QT_NO_CLIPBOARD

#include "command_p.h"

#include <crypto/decryptverifyemailcontroller.h>

#include <utils/input.h>
#include <utils/output.h>

#include <Libkleo/Classify>
#include <Libkleo/Stl_Util>

#include "kleopatra_debug.h"
#include <KLocalizedString>

#include <exception>

using namespace Kleo;
using namespace Kleo::Commands;
using namespace Kleo::Crypto;

class DecryptVerifyClipboardCommand::Private : public Command::Private
{
    friend class ::Kleo::Commands::DecryptVerifyClipboardCommand;
    DecryptVerifyClipboardCommand *q_func() const
    {
        return static_cast<DecryptVerifyClipboardCommand *>(q);
    }

public:
    explicit Private(DecryptVerifyClipboardCommand *qq, KeyListController *c);
    ~Private() override;

    void init();

private:
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
    DecryptVerifyEMailController controller;
};

DecryptVerifyClipboardCommand::Private *DecryptVerifyClipboardCommand::d_func()
{
    return static_cast<Private *>(d.get());
}
const DecryptVerifyClipboardCommand::Private *DecryptVerifyClipboardCommand::d_func() const
{
    return static_cast<const Private *>(d.get());
}

#define d d_func()
#define q q_func()

DecryptVerifyClipboardCommand::Private::Private(DecryptVerifyClipboardCommand *qq, KeyListController *c)
    : Command::Private(qq, c)
    , shared_qq(qq, [](DecryptVerifyClipboardCommand *) {})
    , input()
    , controller({}, Task::DataSource::Clipboard)
{
}

DecryptVerifyClipboardCommand::Private::~Private()
{
    qCDebug(KLEOPATRA_LOG);
}

DecryptVerifyClipboardCommand::DecryptVerifyClipboardCommand(KeyListController *c)
    : Command(new Private(this, c))
{
    d->init();
}

DecryptVerifyClipboardCommand::DecryptVerifyClipboardCommand(QAbstractItemView *v, KeyListController *c)
    : Command(v, new Private(this, c))
{
    d->init();
}

void DecryptVerifyClipboardCommand::Private::init()
{
    controller.setExecutionContext(shared_qq);
    connect(&controller, &Controller::done, q, [this]() {
        slotControllerDone();
    });
    connect(&controller, &Controller::error, q, [this](int err, const QString &details) {
        slotControllerError(err, details);
    });
}

DecryptVerifyClipboardCommand::~DecryptVerifyClipboardCommand()
{
    qCDebug(KLEOPATRA_LOG);
}

// static
bool DecryptVerifyClipboardCommand::canDecryptVerifyCurrentClipboard()
{
    try {
        return Input::createFromClipboard()->classification() & (Class::CipherText | Class::ClearsignedMessage | Class::OpaqueSignature);
    } catch (...) {
    }
    return false;
}

void DecryptVerifyClipboardCommand::doStart()
{
    try {
        const std::shared_ptr<Input> input = Input::createFromClipboard();

        const unsigned int classification = input->classification();

        if (classification & (Class::ClearsignedMessage | Class::OpaqueSignature)) {
            d->controller.setOperation(Verify);
            d->controller.setVerificationMode(Opaque);
        } else if (classification & Class::CipherText) {
            d->controller.setOperation(DecryptVerify);
        } else {
            d->information(i18n("The clipboard does not appear to "
                                "contain a signature or encrypted text."),
                           i18n("Decrypt/Verify Clipboard Error"));
            d->finished();
            return;
        }

        d->controller.setProtocol(findProtocol(classification));
        d->controller.setInput(input);
        d->controller.setOutput(Output::createFromClipboard());

        d->controller.start();

    } catch (const std::exception &e) {
        d->information(i18n("An error occurred: %1", QString::fromLocal8Bit(e.what())), i18n("Decrypt/Verify Clipboard Error"));
        d->finished();
    }
}

void DecryptVerifyClipboardCommand::doCancel()
{
    qCDebug(KLEOPATRA_LOG);
    d->controller.cancel();
}

#undef d
#undef q

#include "moc_decryptverifyclipboardcommand.cpp"

#endif // QT_NO_CLIPBOARD
