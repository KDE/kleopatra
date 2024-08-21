/*  smartcard/netkeycard.cpp

    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2017 Intevation GmbH

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include "netkeycard.h"

#include "keypairinfo.h"

#include "kleopatra_debug.h"

#include <Libkleo/Algorithm>
#include <Libkleo/Formatting>
#include <Libkleo/Predicates>

#include <gpgme++/context.h>
#include <gpgme++/error.h>
#include <gpgme++/keylistresult.h>

#include <memory>
#include <string>

using namespace Kleo;
using namespace Kleo::SmartCard;

// static
const std::string NetKeyCard::AppName = "nks";

NetKeyCard::NetKeyCard(const Card &card)
    : Card(card)
{
    setAppType(AppType::NetKeyApp);
    setAppName(AppName);
    setDisplayAppName(QStringLiteral("NetKey"));
}

// static
std::string NetKeyCard::nksPinKeyRef()
{
    return std::string("PW1.CH");
}

// static
std::string NetKeyCard::sigGPinKeyRef()
{
    return std::string("PW1.CH.SIG");
}

// State 0 -> NKS PIN Retry counter
// State 1 -> NKS PUK Retry counter
// State 2 -> SigG PIN Retry counter
// State 3 -> SigG PUK Retry counter

bool NetKeyCard::hasNKSNullPin() const
{
    static std::string forceNullPinSerialNumber = qgetenv("KLEO_FORCE_NULLPIN").toStdString();
    if (serialNumber() == forceNullPinSerialNumber) {
        return true;
    }

    const auto states = pinStates();
    if (states.size() < 2) {
        qCWarning(KLEOPATRA_LOG) << "Invalid size of pin states:" << states.size();
        return false;
    }
    return states[0] == Card::NullPin;
}

bool NetKeyCard::hasSigGNullPin() const
{
    const auto states = pinStates();
    if (states.size() < 4) {
        qCWarning(KLEOPATRA_LOG) << "Invalid size of pin states:" << states.size();
        return false;
    }
    return states[2] == Card::NullPin;
}

NetKeyCard *NetKeyCard::clone() const
{
    return new NetKeyCard{*this};
}
