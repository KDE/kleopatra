/*
    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2020 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include "changepincommand.h"

#include "cardcommand_p.h"

#include "smartcard/netkeycard.h"
#include "smartcard/openpgpcard.h"
#include "smartcard/pivcard.h"
#include "smartcard/readerstatus.h"

#include <Libkleo/Formatting>

#include <KLocalizedString>

#include <gpgme++/error.h>

#include "kleopatra_debug.h"

using namespace Kleo;
using namespace Kleo::Commands;
using namespace Kleo::SmartCard;
using namespace GpgME;

class ChangePinCommand::Private : public CardCommand::Private
{
    friend class ::Kleo::Commands::ChangePinCommand;
    ChangePinCommand *q_func() const
    {
        return static_cast<ChangePinCommand *>(q);
    }

public:
    explicit Private(ChangePinCommand *qq, const std::string &serialNumber, const std::string &appName, QWidget *p);
    ~Private() override;

    void init();

private:
    void slotResult(const Error &err);

private:
    void changePin();

private:
    std::string appName;
    std::string keyRef;
    ChangePinMode mode = NormalMode;
};

ChangePinCommand::Private *ChangePinCommand::d_func()
{
    return static_cast<Private *>(d.get());
}
const ChangePinCommand::Private *ChangePinCommand::d_func() const
{
    return static_cast<const Private *>(d.get());
}

#define d d_func()
#define q q_func()

ChangePinCommand::Private::Private(ChangePinCommand *qq, const std::string &serialNumber, const std::string &appName_, QWidget *p)
    : CardCommand::Private(qq, serialNumber, p)
    , appName(appName_)
{
}

ChangePinCommand::Private::~Private()
{
    qCDebug(KLEOPATRA_LOG) << "ChangePinCommand::Private::~Private()";
}

ChangePinCommand::ChangePinCommand(const std::string &serialNumber, const std::string &appName, QWidget *p)
    : CardCommand(new Private(this, serialNumber, appName, p))
{
    d->init();
}

void ChangePinCommand::Private::init()
{
}

ChangePinCommand::~ChangePinCommand()
{
    qCDebug(KLEOPATRA_LOG) << "ChangePinCommand::~ChangePinCommand()";
}

void ChangePinCommand::setKeyRef(const std::string &keyRef)
{
    d->keyRef = keyRef;
}

void ChangePinCommand::setMode(ChangePinMode mode)
{
    d->mode = mode;
}

void ChangePinCommand::doStart()
{
    qCDebug(KLEOPATRA_LOG) << "ChangePinCommand::doStart()";

    d->changePin();
}

void ChangePinCommand::doCancel()
{
}

void ChangePinCommand::Private::changePin()
{
    qCDebug(KLEOPATRA_LOG) << "ChangePinCommand::changePin()";

    const auto card = SmartCard::ReaderStatus::instance()->getCard(serialNumber(), appName);
    if (!card) {
        error(i18n("Failed to find the smartcard with the serial number: %1", QString::fromStdString(serialNumber())));
        finished();
        return;
    }

    QByteArrayList command;
    command << "SCD PASSWD";
    if (mode == ResetMode) {
        command << "--reset";
    } else if (mode == NullPinMode) {
        command << "--nullpin";
    }
    command << QByteArray::fromStdString(keyRef);
    ReaderStatus::mutableInstance()->startSimpleTransaction(card, command.join(' '), q, [this](const GpgME::Error &err) {
        slotResult(err);
    });
}

namespace
{
static QString errorMessage(const std::string &keyRef, ChangePinCommand::ChangePinMode mode, const QString &errorText)
{
    // see cmd_passwd() in gpg-card.c
    if (keyRef == PIVCard::pukKeyRef()) {
        return i18nc("@info", "Changing the PUK failed: %1", errorText);
    }
    if (keyRef == OpenPGPCard::resetCodeKeyRef()) {
        if (mode == ChangePinCommand::ResetMode) {
            return i18nc("@info", "Changing the PUK failed: %1", errorText);
        } else {
            return i18nc("@info", "Unblocking the PIN failed: %1", errorText);
        }
    }
    if (keyRef == OpenPGPCard::adminPinKeyRef()) {
        return i18nc("@info", "Changing the Admin PIN failed: %1", errorText);
    }
    if (keyRef == NetKeyCard::nksPinKeyRef()) {
        if (mode == ChangePinCommand::NullPinMode) {
            return i18nc("@info", "Setting the NKS PIN failed: %1", errorText);
        } else {
            return i18nc("@info", "Changing the NKS PIN failed: %1", errorText);
        }
    }
    if (keyRef == NetKeyCard::sigGPinKeyRef()) {
        if (mode == ChangePinCommand::NullPinMode) {
            return i18nc("@info", "Setting the SigG PIN failed: %1", errorText);
        } else {
            return i18nc("@info", "Changing the SigG PIN failed: %1", errorText);
        }
    }
    return i18nc("@info", "Changing the PIN failed: %1", errorText);
}

static QString successMessage(const std::string &keyRef, ChangePinCommand::ChangePinMode mode)
{
    // see cmd_passwd() in gpg-card.c
    if (keyRef == PIVCard::pukKeyRef()) {
        return i18nc("@info", "PUK changed successfully.");
    }
    if (keyRef == OpenPGPCard::resetCodeKeyRef()) {
        if (mode == ChangePinCommand::ResetMode) {
            return i18nc("@info", "PUK changed successfully.");
        } else {
            return i18nc("@info", "Unblocked and set a new PIN successfully.");
        }
    }
    if (keyRef == OpenPGPCard::adminPinKeyRef()) {
        return i18nc("@info", "Admin PIN changed successfully.");
    }
    if (keyRef == NetKeyCard::nksPinKeyRef()) {
        if (mode == ChangePinCommand::NullPinMode) {
            return i18nc("@info", "NKS PIN set successfully.");
        } else {
            return i18nc("@info", "NKS PIN changed successfully.");
        }
    }
    if (keyRef == NetKeyCard::sigGPinKeyRef()) {
        if (mode == ChangePinCommand::NullPinMode) {
            return i18nc("@info", "SigG PIN set successfully.");
        } else {
            return i18nc("@info", "SigG PIN changed successfully.");
        }
    }
    return i18nc("@info", "PIN changed successfully.");
}
}

void ChangePinCommand::Private::slotResult(const GpgME::Error &err)
{
    qCDebug(KLEOPATRA_LOG) << "ChangePinCommand::slotResult():" << Formatting::errorAsString(err) << "(" << err.code() << ")";
    if (err) {
        error(errorMessage(keyRef, mode, Formatting::errorAsString(err)));
    } else if (!err.isCanceled()) {
        success(successMessage(keyRef, mode));
    }
    ReaderStatus::mutableInstance()->updateStatus();
    finished();
}

#undef d
#undef q

#include "moc_changepincommand.cpp"
