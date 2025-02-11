/*
    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2020 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include "setpivcardapplicationadministrationkeycommand.h"

#include "cardcommand_p.h"

#include "smartcard/pivcard.h"
#include "smartcard/readerstatus.h"

#include "commands/authenticatepivcardapplicationcommand.h"

#include "dialogs/pivcardapplicationadministrationkeyinputdialog.h"

#include <Libkleo/Formatting>

#include <KLocalizedString>

#include <gpgme++/error.h>

#include "kleopatra_debug.h"

using namespace Kleo;
using namespace Kleo::Commands;
using namespace Kleo::Dialogs;
using namespace Kleo::SmartCard;
using namespace GpgME;

class SetPIVCardApplicationAdministrationKeyCommand::Private : public CardCommand::Private
{
    friend class ::Kleo::Commands::SetPIVCardApplicationAdministrationKeyCommand;
    SetPIVCardApplicationAdministrationKeyCommand *q_func() const
    {
        return static_cast<SetPIVCardApplicationAdministrationKeyCommand *>(q);
    }

public:
    explicit Private(SetPIVCardApplicationAdministrationKeyCommand *qq, const std::string &serialNumber, QWidget *p);
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
    void setAdminKey();
    void ensureDialogCreated();

private:
    QByteArray newAdminKey;
    QPointer<PIVCardApplicationAdministrationKeyInputDialog> dialog;
    bool hasBeenCanceled = false;
};

SetPIVCardApplicationAdministrationKeyCommand::Private *SetPIVCardApplicationAdministrationKeyCommand::d_func()
{
    return static_cast<Private *>(d.get());
}
const SetPIVCardApplicationAdministrationKeyCommand::Private *SetPIVCardApplicationAdministrationKeyCommand::d_func() const
{
    return static_cast<const Private *>(d.get());
}

#define d d_func()
#define q q_func()

SetPIVCardApplicationAdministrationKeyCommand::Private::Private(SetPIVCardApplicationAdministrationKeyCommand *qq, const std::string &serialNumber, QWidget *p)
    : CardCommand::Private(qq, serialNumber, p)
    , dialog()
{
}

SetPIVCardApplicationAdministrationKeyCommand::Private::~Private()
{
    qCDebug(KLEOPATRA_LOG) << "SetPIVCardApplicationAdministrationKeyCommand::Private::~Private()";
}

SetPIVCardApplicationAdministrationKeyCommand::SetPIVCardApplicationAdministrationKeyCommand(const std::string &serialNumber, QWidget *p)
    : CardCommand(new Private(this, serialNumber, p))
{
    d->init();
}

void SetPIVCardApplicationAdministrationKeyCommand::Private::init()
{
}

SetPIVCardApplicationAdministrationKeyCommand::~SetPIVCardApplicationAdministrationKeyCommand()
{
    qCDebug(KLEOPATRA_LOG) << "SetPIVCardApplicationAdministrationKeyCommand::~SetPIVCardApplicationAdministrationKeyCommand()";
}

void SetPIVCardApplicationAdministrationKeyCommand::doStart()
{
    qCDebug(KLEOPATRA_LOG) << "SetPIVCardApplicationAdministrationKeyCommand::doStart()";

    d->authenticate();
}

void SetPIVCardApplicationAdministrationKeyCommand::doCancel()
{
}

void SetPIVCardApplicationAdministrationKeyCommand::Private::authenticate()
{
    qCDebug(KLEOPATRA_LOG) << "SetPIVCardApplicationAdministrationKeyCommand::authenticate()";

    auto cmd = new AuthenticatePIVCardApplicationCommand(serialNumber(), parentWidgetOrView());
    cmd->setAutoResetCardToOpenPGP(false);
    cmd->setPrompt(i18n("Please enter the old PIV Card Application Administration Key in hex-encoded form."));
    connect(cmd, &AuthenticatePIVCardApplicationCommand::finished, q, [this]() {
        authenticationFinished();
    });
    connect(cmd, &AuthenticatePIVCardApplicationCommand::canceled, q, [this]() {
        authenticationCanceled();
    });
    cmd->start();
}

void SetPIVCardApplicationAdministrationKeyCommand::Private::authenticationFinished()
{
    qCDebug(KLEOPATRA_LOG) << "SetPIVCardApplicationAdministrationKeyCommand::authenticationFinished()";
    if (!hasBeenCanceled) {
        setAdminKey();
    }
}

void SetPIVCardApplicationAdministrationKeyCommand::Private::authenticationCanceled()
{
    qCDebug(KLEOPATRA_LOG) << "SetPIVCardApplicationAdministrationKeyCommand::authenticationCanceled()";
    hasBeenCanceled = true;
    canceled();
}

void SetPIVCardApplicationAdministrationKeyCommand::Private::setAdminKey()
{
    qCDebug(KLEOPATRA_LOG) << "SetPIVCardApplicationAdministrationKeyCommand::setAdminKey()";

    ensureDialogCreated();
    Q_ASSERT(dialog);
    dialog->show();
}

void SetPIVCardApplicationAdministrationKeyCommand::Private::ensureDialogCreated()
{
    if (dialog) {
        return;
    }

    dialog = new PIVCardApplicationAdministrationKeyInputDialog(parentWidgetOrView());
    dialog->setAttribute(Qt::WA_DeleteOnClose);
    dialog->setLabelText(newAdminKey.isEmpty() ? i18n("Please enter the new PIV Card Application Administration Key in hex-encoded form. "
                                                      "The key needs to consist of 24 bytes, i.e. 48 hex-characters.")
                                               : i18n("Please enter the new PIV Card Application Administration Key again."));

    connect(dialog, &QDialog::accepted, q, [this]() {
        slotDialogAccepted();
    });
    connect(dialog, &QDialog::rejected, q, [this]() {
        slotDialogRejected();
    });
}

void SetPIVCardApplicationAdministrationKeyCommand::Private::slotDialogAccepted()
{
    if (newAdminKey.isEmpty()) {
        newAdminKey = dialog->adminKey();
        dialog = nullptr;
        setAdminKey();
        return;
    }

    const QByteArray newAdminKey2 = dialog->adminKey();
    if (newAdminKey != newAdminKey2) {
        error(i18nc("@info", "The two keys you have entered do not match. Please retry."));
        newAdminKey.clear();
        dialog = nullptr;
        setAdminKey();
        return;
    }

    auto pivCard = ReaderStatus::instance()->getCard<PIVCard>(serialNumber());
    if (!pivCard) {
        error(i18n("Failed to find the PIV card with the serial number: %1", QString::fromStdString(serialNumber())));
        finished();
        return;
    }

    const QByteArray plusPercentEncodedAdminKey = newAdminKey.toPercentEncoding().replace(' ', '+');
    const QByteArray command = QByteArray("SCD SETATTR SET-ADM-KEY ") + plusPercentEncodedAdminKey;
    ReaderStatus::mutableInstance()->startSimpleTransaction(pivCard, command, q, [this](const GpgME::Error &err) {
        slotResult(err);
    });
}

void SetPIVCardApplicationAdministrationKeyCommand::Private::slotDialogRejected()
{
    finished();
}

void SetPIVCardApplicationAdministrationKeyCommand::Private::slotResult(const GpgME::Error &err)
{
    qCDebug(KLEOPATRA_LOG) << "SetPIVCardApplicationAdministrationKeyCommand::slotResult():" << Formatting::errorAsString(err) << "(" << err.code() << ")";
    if (err) {
        error(i18nc("@info", "Setting the PIV Card Application Administration Key failed: %1", Formatting::errorAsString(err)));
    } else if (!err.isCanceled()) {
        success(i18nc("@info", "PIV Card Application Administration Key set successfully."));
    }
    ReaderStatus::mutableInstance()->updateStatus();
    finished();
}

#undef d
#undef q

#include "moc_setpivcardapplicationadministrationkeycommand.cpp"
