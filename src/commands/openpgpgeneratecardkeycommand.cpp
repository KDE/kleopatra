/*
    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2022 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include <config-kleopatra.h>

#include "openpgpgeneratecardkeycommand.h"

#include "cardcommand_p.h"

#include "smartcard/algorithminfo.h"
#include "smartcard/openpgpcard.h"
#include "smartcard/readerstatus.h"
#include "smartcard/utils.h"

#include "dialogs/gencardkeydialog.h"

#include <Libkleo/Formatting>

#include <KLocalizedString>

#include <QGpgME/Debug>

#include <gpgme++/error.h>

#include "kleopatra_debug.h"

using namespace Kleo;
using namespace Kleo::Commands;
using namespace Kleo::SmartCard;
using namespace GpgME;

class OpenPGPGenerateCardKeyCommand::Private : public CardCommand::Private
{
    friend class ::Kleo::Commands::OpenPGPGenerateCardKeyCommand;
    OpenPGPGenerateCardKeyCommand *q_func() const
    {
        return static_cast<OpenPGPGenerateCardKeyCommand *>(q);
    }

public:
    explicit Private(OpenPGPGenerateCardKeyCommand *qq, const std::string &keyref, const std::string &serialNumber, QWidget *p);

    void init();

private:
    void slotDialogAccepted();
    void slotDialogRejected();
    void slotResult(const Error &err);

private:
    void ensureDialogCreated();
    void generateKey();

private:
    std::string keyRef;
    bool overwriteExistingKey = false;
    std::string algorithm;
    QPointer<GenCardKeyDialog> dialog;
};

OpenPGPGenerateCardKeyCommand::Private *OpenPGPGenerateCardKeyCommand::d_func()
{
    return static_cast<Private *>(d.get());
}
const OpenPGPGenerateCardKeyCommand::Private *OpenPGPGenerateCardKeyCommand::d_func() const
{
    return static_cast<const Private *>(d.get());
}

#define d d_func()
#define q q_func()

OpenPGPGenerateCardKeyCommand::Private::Private(OpenPGPGenerateCardKeyCommand *qq, const std::string &keyRef_, const std::string &serialNumber, QWidget *p)
    : CardCommand::Private(qq, serialNumber, p)
    , keyRef{keyRef_}
{
}

void OpenPGPGenerateCardKeyCommand::Private::init()
{
}

void OpenPGPGenerateCardKeyCommand::Private::slotDialogAccepted()
{
    algorithm = dialog->getKeyParams().algorithm;
    generateKey();
}

void OpenPGPGenerateCardKeyCommand::Private::slotDialogRejected()
{
    finished();
}

void OpenPGPGenerateCardKeyCommand::Private::slotResult(const GpgME::Error &err)
{
    qCDebug(KLEOPATRA_LOG).nospace() << q << "::Private::" << __func__ << err;

    if (err) {
        error(i18nc("@info", "Generating key failed: %1", Formatting::errorAsString(err)));
    } else if (!err.isCanceled()) {
        success(i18nc("@info", "Key successfully generated."));
    }
    ReaderStatus::mutableInstance()->updateStatus();
    finished();
}

void OpenPGPGenerateCardKeyCommand::Private::ensureDialogCreated()
{
    if (dialog) {
        return;
    }

    dialog = new GenCardKeyDialog(GenCardKeyDialog::KeyAlgorithm, parentWidgetOrView());
    dialog->setAttribute(Qt::WA_DeleteOnClose);

    connect(dialog, &QDialog::accepted, q, [this]() {
        slotDialogAccepted();
    });
    connect(dialog, &QDialog::rejected, q, [this]() {
        slotDialogRejected();
    });
}

void OpenPGPGenerateCardKeyCommand::Private::generateKey()
{
    qCDebug(KLEOPATRA_LOG).nospace() << q << "::Private::" << __func__;

    auto pgpCard = ReaderStatus::instance()->getCard<OpenPGPCard>(serialNumber());
    if (!pgpCard) {
        error(i18n("Failed to find the OpenPGP card with the serial number: %1", QString::fromStdString(serialNumber())));
        finished();
        return;
    }

    QByteArrayList command;
    command << "SCD GENKEY";
    if (overwriteExistingKey) {
        command << "--force";
    }
    if (!algorithm.empty()) {
        command << "--algo=" + QByteArray::fromStdString(OpenPGPCard::getAlgorithmName(algorithm, keyRef));
    }
    command << "--" << QByteArray::fromStdString(keyRef);
    ReaderStatus::mutableInstance()->startSimpleTransaction(pgpCard, command.join(' '), q, [this](const GpgME::Error &err) {
        slotResult(err);
    });
}

OpenPGPGenerateCardKeyCommand::OpenPGPGenerateCardKeyCommand(const std::string &keyref, const std::string &serialNumber, QWidget *p)
    : CardCommand(new Private(this, keyref, serialNumber, p))
{
    d->init();
}

OpenPGPGenerateCardKeyCommand::~OpenPGPGenerateCardKeyCommand()
{
    qCDebug(KLEOPATRA_LOG).nospace() << this << "::" << __func__;
}

void OpenPGPGenerateCardKeyCommand::doStart()
{
    qCDebug(KLEOPATRA_LOG).nospace() << this << "::" << __func__;

    // check if key exists
    auto pgpCard = ReaderStatus::instance()->getCard<OpenPGPCard>(d->serialNumber());
    if (!pgpCard) {
        d->error(i18n("Failed to find the OpenPGP card with the serial number: %1", QString::fromStdString(d->serialNumber())));
        d->finished();
        return;
    }

    auto existingKey = pgpCard->keyInfo(d->keyRef).grip;
    if (!existingKey.empty()) {
        const QString warningText = i18nc("@info",
                                          "<p>This card already contains a key in this slot. Continuing will <b>overwrite</b> that key.</p>"
                                          "<p>If there is no backup the existing key will be irrecoverably lost.</p>")
            + i18n("The existing key has the ID:") + QStringLiteral("<pre>%1</pre>").arg(QString::fromStdString(existingKey))
            + (d->keyRef == OpenPGPCard::pgpEncKeyRef() ? i18n("It will no longer be possible to decrypt past communication encrypted for the existing key.")
                                                        : QString());
        const auto choice = KMessageBox::warningContinueCancel(d->parentWidgetOrView(),
                                                               warningText,
                                                               i18nc("@title:window", "Overwrite Existing Key"),
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
    const auto allowedAlgos = getAllowedAlgorithms(pgpCard->supportedAlgorithms());
    if (allowedAlgos.empty()) {
        d->error(i18nc("@info", "You cannot generate a key on this smart card because it doesn't support any of the compliant algorithms."));
        d->finished();
        return;
    }
    d->dialog->setSupportedAlgorithms(allowedAlgos, getPreferredAlgorithm(allowedAlgos));
    d->dialog->show();
}

void OpenPGPGenerateCardKeyCommand::doCancel()
{
}

#undef d
#undef q

#include "moc_openpgpgeneratecardkeycommand.cpp"
