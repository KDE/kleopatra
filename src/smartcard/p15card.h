/*  smartcard/p15card.h

    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2021 g10 Code GmbH
    SPDX-FileContributor: Andre Heinecke <aheinecke@g10code.com>

    SPDX-License-Identifier: GPL-2.0-or-later
*/
#pragma once

#include "card.h"

namespace Kleo
{
namespace SmartCard
{

/** Class to work with PKCS#15 smartcards or compatible tokens.
 *
 * A PKCS#15 card is pretty generic and there is no real standard
 * for them. It all depends on the Apps running on the cards. This
 * mostly tries to leave it to GnuPG to determine if there are usable
 * things on the card. The generic info on all keys on the card is
 * accessible through keyInfo from the parent class.
 *
 * The specialization is required for specific app support.
 **/
class P15Card : public Card
{
public:
    explicit P15Card(const Card &card);

    static const std::string AppName;

private:
    P15Card(const P15Card &card) = default;

    P15Card *clone() const override;
};

}
}
