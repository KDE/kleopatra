/*  smartcard/utils.cpp

    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2020 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include "utils.h"

#include "algorithminfo.h"
#include "netkeycard.h"
#include "openpgpcard.h"
#include "p15card.h"
#include "pivcard.h"

#include <kleopatra_debug.h>

#include <Libkleo/Algorithm>
#include <Libkleo/Compliance>
#include <Libkleo/GnuPG>

#include <KLocalizedString>

#include <QString>

using namespace Kleo::SmartCard;

std::string Kleo::SmartCard::appName(AppType appType)
{
    switch (appType) {
    case AppType::OpenPGPApp:
        return OpenPGPCard::AppName;
    case AppType::PIVApp:
        return PIVCard::AppName;
    case AppType::NetKeyApp:
        return NetKeyCard::AppName;
    case AppType::P15App:
        return P15Card::AppName;
    case AppType::NoApp:
        break;
    };
    return {};
}

QString Kleo::SmartCard::displayAppName(const std::string &appName)
{
    if (appName == NetKeyCard::AppName) {
        return i18nc("proper name of a type of smartcard", "NetKey");
    } else if (appName == OpenPGPCard::AppName) {
        return i18nc("proper name of a type of smartcard", "OpenPGP");
    } else if (appName == PIVCard::AppName) {
        return i18nc("proper name of a type of smartcard", "PIV");
    } else {
        return QString::fromStdString(appName);
    }
}

QString Kleo::SmartCard::cardKeyDisplayName(const std::string &keyRef)
{
    static const QMap<std::string, QString> displayNames = {
        {OpenPGPCard::pgpSigKeyRef(), i18n("Signature Key")},
        {OpenPGPCard::pgpEncKeyRef(), i18n("Encryption Key")},
        {OpenPGPCard::pgpAuthKeyRef(), i18n("Authentication Key")},
        {PIVCard::pivAuthenticationKeyRef(), i18n("PIV Authentication Key")},
        {PIVCard::cardAuthenticationKeyRef(), i18n("Card Authentication Key")},
        {PIVCard::digitalSignatureKeyRef(), i18n("Digital Signature Key")},
        {PIVCard::keyManagementKeyRef(), i18n("Key Management Key")},
    };

    return displayNames.value(keyRef);
}

std::vector<AlgorithmInfo> Kleo::SmartCard::getAllowedAlgorithms(const std::vector<AlgorithmInfo> &supportedAlgorithms)
{
    std::vector<AlgorithmInfo> result;
    result.reserve(supportedAlgorithms.size());
    Kleo::copy_if(supportedAlgorithms, std::back_inserter(result), [](const auto &algoInfo) {
        return DeVSCompliance::algorithmIsCompliant(algoInfo.id);
    });
    return result;
}

std::string Kleo::SmartCard::getPreferredAlgorithm(const std::vector<AlgorithmInfo> &allowedAlgorithms)
{
    const auto isAllowedAlgorithm = [&allowedAlgorithms](const std::string &algoId) {
        return std::ranges::any_of(allowedAlgorithms, [&algoId](const auto &algoInfo) {
            return algoInfo.id == algoId;
        });
    };

    const auto &preferredAlgos = Kleo::preferredAlgorithms();
    const auto defaultAlgoIt = Kleo::find_if(preferredAlgos, isAllowedAlgorithm);
    if (defaultAlgoIt != preferredAlgos.end()) {
        return *defaultAlgoIt;
    } else {
        qCWarning(KLEOPATRA_LOG) << __func__ << "- No preferred algorithm is allowed. Using first allowed algorithm as default.";
        return !allowedAlgorithms.empty() ? allowedAlgorithms.front().id : std::string{};
    }
}
