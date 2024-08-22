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

NetKeyCard *NetKeyCard::clone() const
{
    return new NetKeyCard{*this};
}
