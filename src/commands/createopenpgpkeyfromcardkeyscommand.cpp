/*
    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2020 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include <config-kleopatra.h>

#include "createopenpgpkeyfromcardkeyscommand.h"

#include "cardcommand_p.h"

#include "dialogs/adduseriddialog.h"

#include "smartcard/netkeycard.h"
#include "smartcard/openpgpcard.h"
#include "smartcard/pivcard.h"
#include "smartcard/readerstatus.h"

#include <Libkleo/Formatting>
#include <Libkleo/KeyCache>

#include <KLocalizedString>

#include <QGpgME/Protocol>
#include <QGpgME/QuickJob>
#include <qgpgme/qgpgme_version.h>

#include <gpgme++/context.h>
#include <gpgme++/engineinfo.h>

#include <gpgme.h>

#include "kleopatra_debug.h"

using namespace Kleo;
using namespace Kleo::Commands;
using namespace Kleo::SmartCard;
using namespace GpgME;
using namespace QGpgME;

class CreateOpenPGPKeyFromCardKeysCommand::Private : public CardCommand::Private
{
    friend class ::Kleo::Commands::CreateOpenPGPKeyFromCardKeysCommand;
    CreateOpenPGPKeyFromCardKeysCommand *q_func() const
    {
        return static_cast<CreateOpenPGPKeyFromCardKeysCommand *>(q);
    }

public:
    explicit Private(CreateOpenPGPKeyFromCardKeysCommand *qq, const std::string &serialNumber, const std::string &appName, QWidget *parent);
    ~Private() override;

private:
    void start();

    void slotDialogAccepted();
    void slotDialogRejected();
    void slotResult(const Error &err);

    void ensureDialogCreated();

private:
    std::string appName;
    QPointer<AddUserIDDialog> dialog;
};

CreateOpenPGPKeyFromCardKeysCommand::Private *CreateOpenPGPKeyFromCardKeysCommand::d_func()
{
    return static_cast<Private *>(d.get());
}
const CreateOpenPGPKeyFromCardKeysCommand::Private *CreateOpenPGPKeyFromCardKeysCommand::d_func() const
{
    return static_cast<const Private *>(d.get());
}

#define d d_func()
#define q q_func()

CreateOpenPGPKeyFromCardKeysCommand::Private::Private(CreateOpenPGPKeyFromCardKeysCommand *qq,
                                                      const std::string &serialNumber,
                                                      const std::string &appName_,
                                                      QWidget *parent)
    : CardCommand::Private(qq, serialNumber, parent)
    , appName(appName_)
{
}

CreateOpenPGPKeyFromCardKeysCommand::Private::~Private()
{
}

void CreateOpenPGPKeyFromCardKeysCommand::Private::start()
{
    if (appName != NetKeyCard::AppName && appName != OpenPGPCard::AppName && appName != PIVCard::AppName) {
        qCWarning(KLEOPATRA_LOG) << "CreateOpenPGPKeyFromCardKeysCommand does not support card application" << QString::fromStdString(appName);
        finished();
        return;
    }

    const auto card = ReaderStatus::instance()->getCard(serialNumber(), appName);
    if (!card) {
        error(i18n("Failed to find the smartcard with the serial number: %1", QString::fromStdString(serialNumber())));
        finished();
        return;
    }

    const auto signingKeyGrip = card->keyInfo(card->signingKeyRef()).grip;
    const Key signingKey = KeyCache::instance()->findSubkeyByKeyGrip(signingKeyGrip, OpenPGP).parent();
    if (!signingKey.isNull()) {
        const QString message = i18nc("@info",
                                      "<p>There is already an OpenPGP key corresponding to the signing key on this card:</p><p>%1</p>"
                                      "<p>Do you still want to create an OpenPGP key for the card keys?</p>",
                                      Formatting::summaryLine(signingKey));
        const auto choice = KMessageBox::warningContinueCancel(parentWidgetOrView(),
                                                               message,
                                                               i18nc("@title:window", "Create OpenPGP Key"),
                                                               KStandardGuiItem::cont(),
                                                               KStandardGuiItem::cancel(),
                                                               QString(),
                                                               KMessageBox::Notify);
        if (choice != KMessageBox::Continue) {
            finished();
            return;
        }
    }

    ensureDialogCreated();

    dialog->setWindowTitle(i18nc("@title:window", "Enter User ID"));
    dialog->setName(card->cardHolder());

    dialog->show();
}

void CreateOpenPGPKeyFromCardKeysCommand::Private::slotDialogAccepted()
{
    const Error err = ReaderStatus::switchCardAndApp(serialNumber(), appName);
    if (err) {
        finished();
        return;
    }

    const auto backend = openpgp();
    if (!backend) {
        finished();
        return;
    }

    QuickJob *const job = backend->quickJob();
    if (!job) {
        finished();
        return;
    }

    connect(job, &QGpgME::QuickJob::result, q, [this](const GpgME::Error &error) {
        slotResult(error);
    });

    const QString userID = Formatting::prettyNameAndEMail(OpenPGP, QString(), dialog->name(), dialog->email());
    const QDateTime expires = QDateTime();
#if QGPGME_VERSION >= QT_VERSION_CHECK(2, 0, 0)
    const Context::CreationFlags flags = Context::CreateForce;
    job->startCreate(userID, "card", expires, flags);
#else
    const unsigned int flags = GPGME_CREATE_FORCE;
    job->startCreate(userID, "card", expires, Key(), flags);
#endif
}

void CreateOpenPGPKeyFromCardKeysCommand::Private::slotDialogRejected()
{
    canceled();
}

void CreateOpenPGPKeyFromCardKeysCommand::Private::slotResult(const Error &err)
{
    if (err.isCanceled()) {
        // do nothing
    } else if (err) {
        error(i18nc("@info", "Creating an OpenPGP key from the card keys failed: %1", Formatting::errorAsString(err)));
    } else {
        success(i18nc("@info", "Successfully generated an OpenPGP key from the card keys."));
    }

    finished();
}

void CreateOpenPGPKeyFromCardKeysCommand::Private::ensureDialogCreated()
{
    if (dialog) {
        return;
    }

    dialog = new AddUserIDDialog;
    applyWindowID(dialog);
    dialog->setAttribute(Qt::WA_DeleteOnClose);

    connect(dialog, &QDialog::accepted, q, [this]() {
        slotDialogAccepted();
    });
    connect(dialog, &QDialog::rejected, q, [this]() {
        slotDialogRejected();
    });
}

CreateOpenPGPKeyFromCardKeysCommand::CreateOpenPGPKeyFromCardKeysCommand(const std::string &serialNumber, const std::string &appName, QWidget *parent)
    : CardCommand(new Private(this, serialNumber, appName, parent))
{
}

CreateOpenPGPKeyFromCardKeysCommand::~CreateOpenPGPKeyFromCardKeysCommand()
{
}

// static
bool CreateOpenPGPKeyFromCardKeysCommand::isSupported()
{
    return !(engineInfo(GpgEngine).engineVersion() < "2.3.0");
}

void CreateOpenPGPKeyFromCardKeysCommand::doStart()
{
    d->start();
}

void CreateOpenPGPKeyFromCardKeysCommand::doCancel()
{
}

#undef d
#undef q

#include "moc_createopenpgpkeyfromcardkeyscommand.cpp"
