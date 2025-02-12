/*
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
#include <KMessageDialog>
#include <QApplication>
#include <QClipboard>

#include <exception>

using namespace Kleo;
using namespace Kleo::Commands;
using namespace Kleo::Crypto;

using namespace Qt::Literals::StringLiterals;

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
    // Don't remove this dialog, it's required to query the clipboard on wayland
    auto dialog = new KMessageDialog(KMessageDialog::Information, i18nc("@info", "Decrypting/Verifying clipboard…"), nullptr);
    dialog->setAttribute(Qt::WA_DeleteOnClose);

    auto onClipboardAvailable = [dialog, this]() {
        dialog->close();
        try {
            const std::shared_ptr<Input> input = Input::createFromClipboard();

            const unsigned int classification = input->classification();

            if (classification & (Class::ClearsignedMessage | Class::OpaqueSignature)) {
                d->controller.setOperation(Verify);
                d->controller.setVerificationMode(Opaque);
            } else if (classification & Class::CipherText) {
                d->controller.setOperation(DecryptVerify);
            } else {
                d->information(
                    i18n("The clipboard does not appear to "
                         "contain signed or encrypted text."));
                d->finished();
                return;
            }

            d->controller.setProtocol(findProtocol(classification));
            d->controller.setInput(input);
            d->controller.setOutput(Output::createFromClipboard());

            d->controller.start();

        } catch (const std::exception &e) {
            d->information(i18n("An error occurred: %1", QString::fromLocal8Bit(e.what())));
            d->finished();
        }
    };

    if (qApp->platformName() != "wayland"_L1) {
        onClipboardAvailable();
    } else {
        dialog->show();
        // On wayland, the clipboard is not available immediately, but QClipboard::dataChanged is always triggered once we can access it.
        connect(
            qApp->clipboard(),
            &QClipboard::dataChanged,
            this,
            [onClipboardAvailable]() {
                onClipboardAvailable();
            },
            Qt::SingleShotConnection);
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
