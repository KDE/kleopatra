#pragma once
/*  smartcard/netkeycard.h

    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2017 Intevation GmbH

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include "card.h"

#include <gpgme++/key.h>

namespace Kleo
{
namespace SmartCard
{
struct KeyPairInfo;

/** Class to work with NetKey smartcards or compatible tokens */
class NetKeyCard : public Card
{
public:
    explicit NetKeyCard(const Card &card);

    static const std::string AppName;

    static std::string nksPinKeyRef();
    static std::string sigGPinKeyRef();

    bool hasSigGNullPin() const;
    bool hasNKSNullPin() const;

private:
    NetKeyCard(const NetKeyCard &card) = default;

    NetKeyCard *clone() const override;
};
} // namespace Smartcard
} // namespace Kleopatra
