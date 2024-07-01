/*  smartcard/pivcard.h

    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2020 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/
#pragma once

#include "card.h"

namespace Kleo
{
namespace SmartCard
{
struct AlgorithmInfo;
struct KeyPairInfo;

/** Class to work with PIV smartcards or compatible tokens */
class PIVCard : public Card
{
public:
    explicit PIVCard(const Card &card);

    static const std::string AppName;

    static std::string pivAuthenticationKeyRef();
    static std::string cardAuthenticationKeyRef();
    static std::string digitalSignatureKeyRef();
    static std::string keyManagementKeyRef();

    static std::string pinKeyRef();
    static std::string pukKeyRef();

    static const std::vector<KeyPairInfo> &supportedKeys();
    static QString keyDisplayName(const std::string &keyRef);
    static std::vector<AlgorithmInfo> supportedAlgorithms(const std::string &keyRef);
};
} // namespace Smartcard
} // namespace Kleopatra
