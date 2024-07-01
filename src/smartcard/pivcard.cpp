/*  smartcard/pivcard.cpp

    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2020 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include "pivcard.h"

#include "algorithminfo.h"
#include "keypairinfo.h"

#include <KLocalizedString>

#include "kleopatra_debug.h"

using namespace Kleo;
using namespace Kleo::SmartCard;

// static
const std::string PIVCard::AppName = "piv";

PIVCard::PIVCard(const Card &card)
    : Card(card)
{
    setAppType(AppType::PIVApp);
    setAppName(AppName);
    setDisplayAppName(QStringLiteral("PIV"));
    setInitialKeyInfos(PIVCard::supportedKeys());
}

// static
std::string PIVCard::pivAuthenticationKeyRef()
{
    return std::string("PIV.9A");
}

// static
std::string PIVCard::cardAuthenticationKeyRef()
{
    return std::string("PIV.9E");
}

// static
std::string PIVCard::digitalSignatureKeyRef()
{
    return std::string("PIV.9C");
}

// static
std::string PIVCard::keyManagementKeyRef()
{
    return std::string("PIV.9D");
}

// static
std::string PIVCard::pinKeyRef()
{
    return std::string("PIV.80");
}

// static
std::string PIVCard::pukKeyRef()
{
    return std::string("PIV.81");
}

// static
const std::vector<KeyPairInfo> &PIVCard::supportedKeys()
{
    static const std::vector<KeyPairInfo> keyInfos = {
        {PIVCard::pivAuthenticationKeyRef(), "", "a", "", ""},
        {PIVCard::cardAuthenticationKeyRef(), "", "a", "", ""},
        {PIVCard::digitalSignatureKeyRef(), "", "sc", "", ""},
        {PIVCard::keyManagementKeyRef(), "", "e", "", ""},
    };

    return keyInfos;
}

// static
QString PIVCard::keyDisplayName(const std::string &keyRef)
{
    static const QMap<std::string, QString> displayNames = {
        {PIVCard::pivAuthenticationKeyRef(), i18n("PIV Authentication Key")},
        {PIVCard::cardAuthenticationKeyRef(), i18n("Card Authentication Key")},
        {PIVCard::digitalSignatureKeyRef(), i18n("Digital Signature Key")},
        {PIVCard::keyManagementKeyRef(), i18n("Key Management Key")},
    };

    return displayNames.value(keyRef);
}

// static
std::vector<AlgorithmInfo> PIVCard::supportedAlgorithms(const std::string &keyRef)
{
    if (keyRef == PIVCard::keyManagementKeyRef()) {
        return {
            {"rsa2048", i18n("RSA key transport (2048 bits)")},
            {"nistp256", i18n("ECDH (Curve P-256)")},
            {"nistp384", i18n("ECDH (Curve P-384)")},
        };
    } else if (keyRef == PIVCard::digitalSignatureKeyRef()) {
        return {
            {"rsa2048", i18n("RSA (2048 bits)")},
            {"nistp256", i18n("ECDSA (Curve P-256)")},
            {"nistp384", i18n("ECDSA (Curve P-384)")},
        };
    }

    // NIST SP 800-78-4 does not allow Curve P-384 for PIV Authentication key or Card Authentication key
    return {
        {"rsa2048", i18n("RSA (2048 bits)")},
        {"nistp256", i18n("ECDSA (Curve P-256)")},
    };
}

std::string PIVCard::certificateData(const std::string &keyRef) const
{
    return cardInfo("KLEO-CERTIFICATE-" + keyRef);
}

void PIVCard::setCertificateData(const std::string &keyRef, const std::string &data)
{
    addCardInfo("KLEO-CERTIFICATE-" + keyRef, data);
}
