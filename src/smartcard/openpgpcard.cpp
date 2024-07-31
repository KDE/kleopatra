/*  smartcard/openpgpcard.cpp

    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2017 Bundesamt für Sicherheit in der Informationstechnik
    SPDX-FileContributor: Intevation GmbH
    SPDX-FileCopyrightText: 2020, 2022 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/

/* Code in this file is partly based on the GNU Privacy Assistant
 * (cm-openpgp.c) git rev. 0a78795146661234070681737b3e08228616441f
 *
 * Whis is:
 * SPDX-FileCopyrightText: 2008, 2009 g 10 Code GmbH
 *
 * And may be licensed under the GNU General Public License
 * as published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 */

#include "openpgpcard.h"

#include "algorithminfo.h"

#include <Libkleo/Algorithm>
#include <Libkleo/Formatting>
#include <Libkleo/GnuPG>

#include <KLocalizedString>

#include "kleopatra_debug.h"

using namespace Kleo;
using namespace Kleo::SmartCard;

// static
const std::string OpenPGPCard::AppName = "openpgp";

OpenPGPCard::OpenPGPCard(const Card &card)
    : Card(card)
{
    setAppType(AppType::OpenPGPApp);
    setAppName(AppName);
    setDisplayAppName(QStringLiteral("OpenPGP"));
    setInitialKeyInfos(OpenPGPCard::supportedKeys());
}

// static
std::string OpenPGPCard::pgpSigKeyRef()
{
    return std::string("OPENPGP.1");
}

// static
std::string OpenPGPCard::pgpEncKeyRef()
{
    return std::string("OPENPGP.2");
}

// static
std::string OpenPGPCard::pgpAuthKeyRef()
{
    return std::string("OPENPGP.3");
}

// static
std::string OpenPGPCard::pinKeyRef()
{
    return std::string("OPENPGP.1");
}

// static
std::string OpenPGPCard::adminPinKeyRef()
{
    return std::string("OPENPGP.3");
}

// static
std::string OpenPGPCard::resetCodeKeyRef()
{
    return std::string("OPENPGP.2");
}

// static
const std::vector<KeyPairInfo> &OpenPGPCard::supportedKeys()
{
    static const std::vector<KeyPairInfo> keyInfos = {
        {OpenPGPCard::pgpSigKeyRef(), "", "sc", {}, ""},
        {OpenPGPCard::pgpEncKeyRef(), "", "e", {}, ""},
        {OpenPGPCard::pgpAuthKeyRef(), "", "a", {}, ""},
    };

    return keyInfos;
}

// static
std::string OpenPGPCard::getAlgorithmName(const std::string &algorithm, const std::string &keyRef)
{
    static const std::map<std::string, std::string> ecdhAlgorithmMapping = {
        {"curve25519", "cv25519"},
        {"curve448", "cv448"},
    };
    static const std::map<std::string, std::string> eddsaAlgorithmMapping = {
        {"curve25519", "ed25519"},
        {"curve448", "ed448"},
    };
    if (keyRef == OpenPGPCard::pgpEncKeyRef()) {
        const auto it = ecdhAlgorithmMapping.find(algorithm);
        if (it != ecdhAlgorithmMapping.end()) {
            return it->second;
        }
    } else {
        const auto it = eddsaAlgorithmMapping.find(algorithm);
        if (it != eddsaAlgorithmMapping.end()) {
            return it->second;
        }
    }
    return algorithm;
}

void OpenPGPCard::setSupportedAlgorithms(const std::vector<std::string> &algorithms)
{
    const auto &availableAlgos = Kleo::availableAlgorithms();
    const auto &ignoredAlgos = Kleo::ignoredAlgorithms();
    mAlgorithms.clear();
    Kleo::copy_if(algorithms, std::back_inserter(mAlgorithms), [&availableAlgos](const auto &algo) {
        return Kleo::contains(availableAlgos, algo);
    });
    if (mAlgorithms.size() < algorithms.size()) {
        std::vector<std::string> unsupportedAlgos;
        Kleo::copy_if(algorithms, std::back_inserter(unsupportedAlgos), [&availableAlgos, &ignoredAlgos](const auto &algo) {
            return !Kleo::contains(ignoredAlgos, algo) && !Kleo::contains(availableAlgos, algo);
        });
        if (unsupportedAlgos.size() > 0) {
            qCWarning(KLEOPATRA_LOG).nospace() << "OpenPGPCard::" << __func__ << " Unsupported algorithms: " << unsupportedAlgos
                                               << " (supported: " << availableAlgos << ")";
        }
    }
}

std::string OpenPGPCard::pubkeyUrl() const
{
    return cardInfo("PUBKEY-URL");
}

std::vector<AlgorithmInfo> OpenPGPCard::supportedAlgorithms() const
{
    std::vector<AlgorithmInfo> algos;
    std::transform(mAlgorithms.cbegin(), mAlgorithms.cend(), std::back_inserter(algos), [](const auto &algo) {
        return AlgorithmInfo{algo, Formatting::prettyAlgorithmName(algo)};
    });
    return algos;
}

bool OpenPGPCard::isSupportedAlgorithm(const std::string &algorithm) const
{
    return Kleo::contains(mAlgorithms, algorithm);
}

OpenPGPCard *OpenPGPCard::clone() const
{
    return new OpenPGPCard{*this};
}
