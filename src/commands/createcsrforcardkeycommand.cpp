/*
    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2020 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include <config-kleopatra.h>

#include "createcsrforcardkeycommand.h"

#include "cardcommand_p.h"

#include <dialogs/createcsrdialog.h>

#include "smartcard/netkeycard.h"
#include "smartcard/openpgpcard.h"
#include "smartcard/pivcard.h"
#include "smartcard/readerstatus.h"

#include <utils/csrutils.h>

#include <Libkleo/Formatting>
#include <Libkleo/KeyParameters>
#include <Libkleo/KeyUsage>

#include <KLocalizedString>

#include <QGpgME/KeyGenerationJob>
#include <QGpgME/Protocol>

#include <gpgme++/context.h>
#include <gpgme++/keygenerationresult.h>

#include <gpgme.h>

#include <kleopatra_debug.h>

using namespace Kleo;
using namespace Kleo::Commands;
using namespace Kleo::SmartCard;
using namespace GpgME;
using namespace QGpgME;

class CreateCSRForCardKeyCommand::Private : public CardCommand::Private
{
    friend class ::Kleo::Commands::CreateCSRForCardKeyCommand;
    CreateCSRForCardKeyCommand *q_func() const
    {
        return static_cast<CreateCSRForCardKeyCommand *>(q);
    }

public:
    explicit Private(CreateCSRForCardKeyCommand *qq, const std::string &keyRef, const std::string &serialNumber, const std::string &appName, QWidget *parent);
    ~Private() override;

private:
    void start();

    void slotDialogAccepted();
    void slotDialogRejected();
    void slotResult(const KeyGenerationResult &result, const QByteArray &request);

    void ensureDialogCreated();

private:
    std::string appName;
    std::string keyRef;
    KeyParameters keyParameters;
    QPointer<CreateCSRDialog> dialog;
};

CreateCSRForCardKeyCommand::Private *CreateCSRForCardKeyCommand::d_func()
{
    return static_cast<Private *>(d.get());
}
const CreateCSRForCardKeyCommand::Private *CreateCSRForCardKeyCommand::d_func() const
{
    return static_cast<const Private *>(d.get());
}

#define d d_func()
#define q q_func()

CreateCSRForCardKeyCommand::Private::Private(CreateCSRForCardKeyCommand *qq,
                                             const std::string &keyRef_,
                                             const std::string &serialNumber,
                                             const std::string &appName_,
                                             QWidget *parent)
    : CardCommand::Private(qq, serialNumber, parent)
    , appName(appName_)
    , keyRef(keyRef_)
{
}

CreateCSRForCardKeyCommand::Private::~Private()
{
}

static KeyUsage getKeyUsage(const KeyPairInfo &keyInfo)
{
    // note: gpgsm does not support creating CSRs for authentication certificates
    KeyUsage usage;
    if (keyInfo.canCertify()) {
        usage.setCanCertify(true);
    }
    if (keyInfo.canSign()) {
        usage.setCanSign(true);
    }
    if (keyInfo.canEncrypt()) {
        usage.setCanEncrypt(true);
    }
    return usage;
}

void CreateCSRForCardKeyCommand::Private::start()
{
    if (appName != NetKeyCard::AppName && appName != OpenPGPCard::AppName && appName != PIVCard::AppName) {
        qCWarning(KLEOPATRA_LOG) << "CreateCSRForCardKeyCommand does not support card application" << QString::fromStdString(appName);
        finished();
        return;
    }

    const auto card = ReaderStatus::instance()->getCard(serialNumber(), appName);
    if (!card) {
        error(i18n("Failed to find the smartcard with the serial number: %1", QString::fromStdString(serialNumber())));
        finished();
        return;
    }

    ensureDialogCreated();

    if (!card->cardHolder().isEmpty()) {
        dialog->setName(card->cardHolder());
    }
    const KeyPairInfo &keyInfo = card->keyInfo(keyRef);
    dialog->setUsage(getKeyUsage(keyInfo));
    dialog->setAlgorithm(QString::fromStdString(keyInfo.algorithm));
    dialog->setReadOnly(CreateCSRDialog::Algorithm | CreateCSRDialog::Usage);

    dialog->show();
}

void CreateCSRForCardKeyCommand::Private::slotDialogAccepted()
{
    const Error err = ReaderStatus::switchCardAndApp(serialNumber(), appName);
    if (err) {
        finished();
        return;
    }

    const auto backend = smime();
    if (!backend) {
        finished();
        return;
    }

    KeyGenerationJob *const job = backend->keyGenerationJob();
    if (!job) {
        finished();
        return;
    }

    Job::context(job)->setArmor(true);

    connect(job, &KeyGenerationJob::result, q, [this](const GpgME::KeyGenerationResult &result, const QByteArray &pubKeyData) {
        slotResult(result, pubKeyData);
    });

    keyParameters = dialog->keyParameters();
    keyParameters.setCardKeyRef(QString::fromStdString(keyRef));
    // clear key parameters that are implicitly defined by the card key
    keyParameters.setKeyType(Subkey::AlgoUnknown);
    keyParameters.setKeyLength(0);
    keyParameters.setKeyCurve({});

    if (const Error err = job->start(keyParameters.toString())) {
        error(i18nc("@info", "Creating a CSR for the card key failed:\n%1", Formatting::errorAsString(err)));
        finished();
    }
}

void CreateCSRForCardKeyCommand::Private::slotDialogRejected()
{
    canceled();
}

void CreateCSRForCardKeyCommand::Private::slotResult(const KeyGenerationResult &result, const QByteArray &request)
{
    if (result.error().isCanceled()) {
        // do nothing
    } else if (result.error()) {
        error(i18nc("@info", "Creating a CSR for the card key failed:\n%1", Formatting::errorAsString(result.error())));
    } else {
        Kleo::saveCSR(request, keyParameters, parentWidgetOrView());
    }

    finished();
}

void CreateCSRForCardKeyCommand::Private::ensureDialogCreated()
{
    if (dialog) {
        return;
    }

    dialog = new CreateCSRDialog;
    applyWindowID(dialog);
    dialog->setAttribute(Qt::WA_DeleteOnClose);

    connect(dialog, &QDialog::accepted, q, [this]() {
        slotDialogAccepted();
    });
    connect(dialog, &QDialog::rejected, q, [this]() {
        slotDialogRejected();
    });
}

CreateCSRForCardKeyCommand::CreateCSRForCardKeyCommand(const std::string &keyRef, const std::string &serialNumber, const std::string &appName, QWidget *parent)
    : CardCommand(new Private(this, keyRef, serialNumber, appName, parent))
{
}

CreateCSRForCardKeyCommand::~CreateCSRForCardKeyCommand()
{
}

void CreateCSRForCardKeyCommand::doStart()
{
    d->start();
}

void CreateCSRForCardKeyCommand::doCancel()
{
}

#undef d
#undef q

#include "moc_createcsrforcardkeycommand.cpp"
