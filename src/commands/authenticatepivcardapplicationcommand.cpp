/*
    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2020 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include "authenticatepivcardapplicationcommand.h"

#include "cardcommand_p.h"

#include "smartcard/pivcard.h"
#include "smartcard/readerstatus.h"

#include "dialogs/pivcardapplicationadministrationkeyinputdialog.h"

#include <Libkleo/Formatting>

#include <KLocalizedString>

#include <gpgme++/error.h>

#include <gpg-error.h>
#if GPG_ERROR_VERSION_NUMBER >= 0x12400 // 1.36
#define GPG_ERROR_HAS_BAD_AUTH
#endif

#include "kleopatra_debug.h"

using namespace Kleo;
using namespace Kleo::Commands;
using namespace Kleo::Dialogs;
using namespace Kleo::SmartCard;
using namespace GpgME;

class AuthenticatePIVCardApplicationCommand::Private : public CardCommand::Private
{
    friend class ::Kleo::Commands::AuthenticatePIVCardApplicationCommand;
    AuthenticatePIVCardApplicationCommand *q_func() const
    {
        return static_cast<AuthenticatePIVCardApplicationCommand *>(q);
    }

public:
    explicit Private(AuthenticatePIVCardApplicationCommand *qq, const std::string &serialNumber, QWidget *p);
    ~Private() override;

    void init();

private:
    void slotResult(const Error &err);
    void slotDialogAccepted();
    void slotDialogRejected();

private:
    void authenticate(const QByteArray &adminKey);
    void retryAskingForKey();
    void ensureDialogCreated();

private:
    QString prompt;
    QPointer<PIVCardApplicationAdministrationKeyInputDialog> dialog;
};

AuthenticatePIVCardApplicationCommand::Private *AuthenticatePIVCardApplicationCommand::d_func()
{
    return static_cast<Private *>(d.get());
}
const AuthenticatePIVCardApplicationCommand::Private *AuthenticatePIVCardApplicationCommand::d_func() const
{
    return static_cast<const Private *>(d.get());
}

#define d d_func()
#define q q_func()

AuthenticatePIVCardApplicationCommand::Private::Private(AuthenticatePIVCardApplicationCommand *qq, const std::string &serialNumber, QWidget *p)
    : CardCommand::Private(qq, serialNumber, p)
    , dialog()
{
}

AuthenticatePIVCardApplicationCommand::Private::~Private()
{
    qCDebug(KLEOPATRA_LOG) << "AuthenticatePIVCardApplicationCommand::Private::~Private()";
}

AuthenticatePIVCardApplicationCommand::AuthenticatePIVCardApplicationCommand(const std::string &serialNumber, QWidget *p)
    : CardCommand(new Private(this, serialNumber, p))
{
    d->init();
}

void AuthenticatePIVCardApplicationCommand::Private::init()
{
}

AuthenticatePIVCardApplicationCommand::~AuthenticatePIVCardApplicationCommand()
{
    qCDebug(KLEOPATRA_LOG) << "AuthenticatePIVCardApplicationCommand::~AuthenticatePIVCardApplicationCommand()";
}

void AuthenticatePIVCardApplicationCommand::setPrompt(const QString &prompt)
{
    d->prompt = prompt;
}

void AuthenticatePIVCardApplicationCommand::doStart()
{
    qCDebug(KLEOPATRA_LOG) << "AuthenticatePIVCardApplicationCommand::doStart()";

    // at first, try to authenticate using the default application administration key
    d->authenticate(QByteArray::fromHex("010203040506070801020304050607080102030405060708"));
}

void AuthenticatePIVCardApplicationCommand::doCancel()
{
}

void AuthenticatePIVCardApplicationCommand::Private::authenticate(const QByteArray &adminKey)
{
    qCDebug(KLEOPATRA_LOG) << "AuthenticatePIVCardApplicationCommand::authenticate()";

    const auto pivCard = SmartCard::ReaderStatus::instance()->getCard<PIVCard>(serialNumber());
    if (!pivCard) {
        error(i18n("Failed to find the PIV card with the serial number: %1", QString::fromStdString(serialNumber())));
        finished();
        return;
    }

    const QByteArray plusPercentEncodedAdminKey = adminKey.toPercentEncoding().replace(' ', '+');
    const QByteArray command = QByteArray("SCD SETATTR AUTH-ADM-KEY ") + plusPercentEncodedAdminKey;
    ReaderStatus::mutableInstance()->startSimpleTransaction(pivCard, command, q, [this](const GpgME::Error &err) {
        slotResult(err);
    });
}

void AuthenticatePIVCardApplicationCommand::Private::slotResult(const Error &err)
{
    qCDebug(KLEOPATRA_LOG) << "AuthenticatePIVCardApplicationCommand::slotResult():" << Formatting::errorAsString(err) << "(" << err.code() << ")";
    if (err.isCanceled()) {
        canceled();
        return;
    }
    if (err) {
#ifdef GPG_ERROR_HAS_BAD_AUTH
        if (err.code() == GPG_ERR_BAD_AUTH) {
            retryAskingForKey();
            return;
        }
#endif
        error(i18nc("@info", "Authenticating to the card failed: %1", Formatting::errorAsString(err)));
    }
    finished();
}

void AuthenticatePIVCardApplicationCommand::Private::retryAskingForKey()
{
    ensureDialogCreated();
    Q_ASSERT(dialog);
    dialog->show();
}

void AuthenticatePIVCardApplicationCommand::Private::ensureDialogCreated()
{
    if (dialog) {
        return;
    }

    dialog = new PIVCardApplicationAdministrationKeyInputDialog(parentWidgetOrView());
    dialog->setAttribute(Qt::WA_DeleteOnClose);
    dialog->setLabelText(prompt.isEmpty() ? i18n("Please enter the PIV Card Application Administration Key in hex-encoded form.") : prompt);

    connect(dialog, &QDialog::accepted, q, [this]() {
        slotDialogAccepted();
    });
    connect(dialog, &QDialog::rejected, q, [this]() {
        slotDialogRejected();
    });
}

void AuthenticatePIVCardApplicationCommand::Private::slotDialogAccepted()
{
    authenticate(dialog->adminKey());
}

void AuthenticatePIVCardApplicationCommand::Private::slotDialogRejected()
{
    canceled();
}

#undef d
#undef q

#include "moc_authenticatepivcardapplicationcommand.cpp"
