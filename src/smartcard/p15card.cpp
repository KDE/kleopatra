/*  smartcard/p15card.cpp

    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2021 g10 Code GmbH
    SPDX-FileContributor: Andre Heinecke <aheinecke@g10code.com>

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include "p15card.h"

using namespace Kleo::SmartCard;

// static
const std::string P15Card::AppName = "p15";

P15Card::P15Card(const Card &card)
    : Card(card)
{
    setAppType(AppType::P15App);
    setAppName(AppName);
    setDisplayAppName(QStringLiteral("PKCS#15"));
}

P15Card *P15Card::clone() const
{
    return new P15Card{*this};
}
