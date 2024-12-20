/* -*- mode: c++; c-basic-offset:4 -*-
    commands/signclipboardcommand.cpp

    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2008 Klarälvdalens Datakonsult AB

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include <config-kleopatra.h>

#include "signclipboardcommand.h"

#ifndef QT_NO_CLIPBOARD

#include "command_p.h"

#include <crypto/signemailcontroller.h>

#include <utils/input.h>
#include <utils/output.h>

#include <Libkleo/Stl_Util>

#include "kleopatra_debug.h"
#include <KLocalizedString>
#include <KMessageDialog>

#include <QApplication>
#include <QClipboard>
#include <QMimeData>

#include <exception>

using namespace Kleo;
using namespace Kleo::Commands;
using namespace Kleo::Crypto;

using namespace Qt::Literals::StringLiterals;

class SignClipboardCommand::Private : public Command::Private
{
    friend class ::Kleo::Commands::SignClipboardCommand;
    SignClipboardCommand *q_func() const
    {
        return static_cast<SignClipboardCommand *>(q);
    }

public:
    explicit Private(SignClipboardCommand *qq, KeyListController *c);
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
    SignEMailController controller;
};

SignClipboardCommand::Private *SignClipboardCommand::d_func()
{
    return static_cast<Private *>(d.get());
}
const SignClipboardCommand::Private *SignClipboardCommand::d_func() const
{
    return static_cast<const Private *>(d.get());
}

#define d d_func()
#define q q_func()

SignClipboardCommand::Private::Private(SignClipboardCommand *qq, KeyListController *c)
    : Command::Private(qq, c)
    , shared_qq(qq, [](SignClipboardCommand *) {})
    , input()
    , controller(SignEMailController::ClipboardMode)
{
}

SignClipboardCommand::Private::~Private()
{
    qCDebug(KLEOPATRA_LOG);
}

SignClipboardCommand::SignClipboardCommand(GpgME::Protocol protocol, KeyListController *c)
    : Command(new Private(this, c))
{
    d->init();
    d->controller.setProtocol(protocol);
}

SignClipboardCommand::SignClipboardCommand(GpgME::Protocol protocol, QAbstractItemView *v, KeyListController *c)
    : Command(v, new Private(this, c))
{
    d->init();
    d->controller.setProtocol(protocol);
}

void SignClipboardCommand::Private::init()
{
    controller.setExecutionContext(shared_qq);
    controller.setDetachedSignature(false);
    connect(&controller, &Controller::done, q, [this]() {
        slotControllerDone();
    });
    connect(&controller, &Controller::error, q, [this](int err, const QString &details) {
        slotControllerError(err, details);
    });
}

SignClipboardCommand::~SignClipboardCommand()
{
    qCDebug(KLEOPATRA_LOG);
}

// static
bool SignClipboardCommand::canSignCurrentClipboard()
{
    bool canSign = false;
    if (const QClipboard *const clip = QApplication::clipboard()) {
        if (const QMimeData *const mime = clip->mimeData()) {
            canSign = mime->hasText();
        }
    }
    return canSign;
}

void SignClipboardCommand::doStart()
{
    // Don't remove this dialog, it's required to query the clipboard on wayland
    auto dialog = new KMessageDialog(KMessageDialog::Information, i18nc("@info", "Signing clipboard…"), nullptr);
    dialog->setAttribute(Qt::WA_DeleteOnClose);

    auto onClipboardAvailable = [dialog, this]() {
        dialog->close();
        try {
            // snapshot clipboard content here, in case it's being changed...
            d->input = Input::createFromClipboard();

            if (d->input->size() == 0) {
                d->information(i18nc("@info", "The clipboard is empty"));
                d->finished();
                return;
            }

            connect(&d->controller, &SignEMailController::signersResolved, this, [this]() {
                d->slotSignersResolved();
            });

            d->controller.startResolveSigners();

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

void SignClipboardCommand::Private::slotSignersResolved()
{
    try {
        controller.setInputAndOutput(input, Output::createFromClipboard());
        input.reset(); // no longer needed, so don't keep a reference
        controller.start();
    } catch (const std::exception &e) {
        information(i18n("An error occurred: %1", QString::fromLocal8Bit(e.what())));
        finished();
    }
}

void SignClipboardCommand::doCancel()
{
    qCDebug(KLEOPATRA_LOG);
    d->controller.cancel();
}

#undef d
#undef q

#include "moc_signclipboardcommand.cpp"

#endif // QT_NO_CLIPBOARD
