/*
    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2020 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include "pivgeneratecardkeycommand.h"

#include "cardcommand_p.h"

#include "smartcard/algorithminfo.h"
#include "smartcard/pivcard.h"
#include "smartcard/readerstatus.h"

#include "commands/authenticatepivcardapplicationcommand.h"

#include "dialogs/gencardkeydialog.h"

#include <Libkleo/Formatting>

#include <KLocalizedString>

#include <gpgme++/error.h>

#include <gpg-error.h>
#if GPG_ERROR_VERSION_NUMBER >= 0x12400 // 1.36
#define GPG_ERROR_HAS_NO_AUTH
#endif

#include "kleopatra_debug.h"

using namespace Kleo;
using namespace Kleo::Commands;
using namespace Kleo::SmartCard;
using namespace GpgME;

class PIVGenerateCardKeyCommand::Private : public CardCommand::Private
{
    friend class ::Kleo::Commands::PIVGenerateCardKeyCommand;
    PIVGenerateCardKeyCommand *q_func() const
    {
        return static_cast<PIVGenerateCardKeyCommand *>(q);
    }

public:
    explicit Private(PIVGenerateCardKeyCommand *qq, const std::string &serialNumber, QWidget *p);
    ~Private() override;

    void init();

private:
    void slotDialogAccepted();
    void slotDialogRejected();
    void slotResult(const Error &err);

private:
    void authenticate();
    void authenticationFinished();
    void authenticationCanceled();
    void generateKey();
    void ensureDialogCreated();

private:
    std::string keyRef;
    bool overwriteExistingKey = false;
    std::string algorithm;
    QPointer<GenCardKeyDialog> dialog;
    bool hasBeenCanceled = false;
};

PIVGenerateCardKeyCommand::Private *PIVGenerateCardKeyCommand::d_func()
{
    return static_cast<Private *>(d.get());
}
const PIVGenerateCardKeyCommand::Private *PIVGenerateCardKeyCommand::d_func() const
{
    return static_cast<const Private *>(d.get());
}

#define d d_func()
#define q q_func()

PIVGenerateCardKeyCommand::Private::Private(PIVGenerateCardKeyCommand *qq, const std::string &serialNumber, QWidget *p)
    : CardCommand::Private(qq, serialNumber, p)
    , dialog()
{
}

PIVGenerateCardKeyCommand::Private::~Private()
{
    qCDebug(KLEOPATRA_LOG) << "PIVGenerateCardKeyCommand::Private::~Private()";
}

PIVGenerateCardKeyCommand::PIVGenerateCardKeyCommand(const std::string &serialNumber, QWidget *p)
    : CardCommand(new Private(this, serialNumber, p))
{
    d->init();
}

void PIVGenerateCardKeyCommand::Private::init()
{
}

PIVGenerateCardKeyCommand::~PIVGenerateCardKeyCommand()
{
    qCDebug(KLEOPATRA_LOG) << "PIVGenerateCardKeyCommand::~PIVGenerateCardKeyCommand()";
}

void PIVGenerateCardKeyCommand::setKeyRef(const std::string &keyRef)
{
    d->keyRef = keyRef;
}

void PIVGenerateCardKeyCommand::doStart()
{
    qCDebug(KLEOPATRA_LOG) << "PIVGenerateCardKeyCommand::doStart()";

    // check if key exists
    auto pivCard = ReaderStatus::instance()->getCard<PIVCard>(d->serialNumber());
    if (!pivCard) {
        d->error(i18n("Failed to find the PIV card with the serial number: %1", QString::fromStdString(d->serialNumber())));
        d->finished();
        return;
    }

    auto existingKey = pivCard->keyInfo(d->keyRef).grip;
    if (!existingKey.empty()) {
        const QString warningText = i18nc("@info",
                                          "<p>This card already contains a key in this slot. Continuing will <b>overwrite</b> that key.</p>"
                                          "<p>If there is no backup the existing key will be irrecoverably lost.</p>")
            + i18n("The existing key has the ID:") + QStringLiteral("<pre>%1</pre>").arg(QString::fromStdString(existingKey))
            + (d->keyRef == PIVCard::keyManagementKeyRef() ? i18n("It will no longer be possible to decrypt past communication encrypted for the existing key.")
                                                           : QString());
        const auto choice = KMessageBox::warningContinueCancel(d->parentWidgetOrView(),
                                                               warningText,
                                                               i18nc("@title:window", "Overwrite existing key"),
                                                               KStandardGuiItem::cont(),
                                                               KStandardGuiItem::cancel(),
                                                               QString(),
                                                               KMessageBox::Notify | KMessageBox::Dangerous);
        if (choice != KMessageBox::Continue) {
            d->finished();
            return;
        }
        d->overwriteExistingKey = true;
    }

    d->ensureDialogCreated();
    Q_ASSERT(d->dialog);
    d->dialog->show();
}

void PIVGenerateCardKeyCommand::doCancel()
{
}

void PIVGenerateCardKeyCommand::Private::authenticate()
{
    qCDebug(KLEOPATRA_LOG) << "PIVGenerateCardKeyCommand::authenticate()";

    auto cmd = new AuthenticatePIVCardApplicationCommand(serialNumber(), parentWidgetOrView());
    cmd->setAutoResetCardToOpenPGP(false);
    connect(cmd, &AuthenticatePIVCardApplicationCommand::finished, q, [this]() {
        authenticationFinished();
    });
    connect(cmd, &AuthenticatePIVCardApplicationCommand::canceled, q, [this]() {
        authenticationCanceled();
    });
    cmd->start();
}

void PIVGenerateCardKeyCommand::Private::authenticationFinished()
{
    qCDebug(KLEOPATRA_LOG) << "PIVGenerateCardKeyCommand::authenticationFinished()";
    if (!hasBeenCanceled) {
        generateKey();
    }
}

void PIVGenerateCardKeyCommand::Private::authenticationCanceled()
{
    qCDebug(KLEOPATRA_LOG) << "PIVGenerateCardKeyCommand::authenticationCanceled()";
    hasBeenCanceled = true;
    canceled();
}

void PIVGenerateCardKeyCommand::Private::generateKey()
{
    qCDebug(KLEOPATRA_LOG) << "PIVGenerateCardKeyCommand::generateKey()";

    auto pivCard = ReaderStatus::instance()->getCard<PIVCard>(serialNumber());
    if (!pivCard) {
        error(i18n("Failed to find the PIV card with the serial number: %1", QString::fromStdString(serialNumber())));
        finished();
        return;
    }

    QByteArrayList command;
    command << "SCD GENKEY";
    if (overwriteExistingKey) {
        command << "--force";
    }
    if (!algorithm.empty()) {
        command << "--algo=" + QByteArray::fromStdString(algorithm);
    }
    command << "--" << QByteArray::fromStdString(keyRef);
    ReaderStatus::mutableInstance()->startSimpleTransaction(pivCard, command.join(' '), q, [this](const GpgME::Error &err) {
        slotResult(err);
    });
}

void PIVGenerateCardKeyCommand::Private::slotResult(const GpgME::Error &err)
{
    qCDebug(KLEOPATRA_LOG) << "PIVGenerateCardKeyCommand::slotResult():" << Formatting::errorAsString(err) << "(" << err.code() << ")";
    if (err) {
#ifdef GPG_ERROR_HAS_NO_AUTH
        if (err.code() == GPG_ERR_NO_AUTH) {
            authenticate();
            return;
        }
#endif

        error(i18nc("@info", "Generating key failed: %1", Formatting::errorAsString(err)));
    } else if (!err.isCanceled()) {
        success(i18nc("@info", "Key successfully generated."));
    }
    ReaderStatus::mutableInstance()->updateStatus();
    finished();
}

void PIVGenerateCardKeyCommand::Private::slotDialogAccepted()
{
    algorithm = dialog->getKeyParams().algorithm;

    // assume that we are already authenticated to the card
    generateKey();
}

void PIVGenerateCardKeyCommand::Private::slotDialogRejected()
{
    finished();
}

void PIVGenerateCardKeyCommand::Private::ensureDialogCreated()
{
    if (dialog) {
        return;
    }

    dialog = new GenCardKeyDialog(GenCardKeyDialog::KeyAlgorithm, parentWidgetOrView());
    dialog->setAttribute(Qt::WA_DeleteOnClose);
    dialog->setSupportedAlgorithms(PIVCard::supportedAlgorithms(keyRef), "rsa2048");

    connect(dialog, &QDialog::accepted, q, [this]() {
        slotDialogAccepted();
    });
    connect(dialog, &QDialog::rejected, q, [this]() {
        slotDialogRejected();
    });
}

#undef d
#undef q

#include "moc_pivgeneratecardkeycommand.cpp"
