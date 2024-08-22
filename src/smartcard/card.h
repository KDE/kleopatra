#pragma once
/*  smartcard/card.h

    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2017 Bundesamt für Sicherheit in der Informationstechnik
    SPDX-FileContributor: Intevation GmbH

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include "keypairinfo.h"

#include <map>
#include <string>
#include <vector>

#include <QString>

namespace Kleo
{
namespace SmartCard
{

enum class AppType {
    NoApp,
    OpenPGPApp,
    PIVApp,
    NetKeyApp,
    P15App,
};

/** Class representing an application on a smartcard or similar hardware token. */
class Card
{
public:
    enum PinState {
        UnknownPinState,
        NullPin,
        PinBlocked,
        NoPin,
        PinOk,

        NumPinStates
    };

    enum Status {
        NoCard,
        CardPresent,
        CardActive,
        CardUsable,

        _NumScdStates,

        CardError = _NumScdStates,

        NumStates
    };

    Card();
    virtual ~Card();

    virtual Card *clone() const;

    virtual bool operator==(const Card &other) const;
    bool operator!=(const Card &other) const;

    AppType appType() const;

    void setStatus(Status s);
    Status status() const;

    void setSerialNumber(const std::string &sn);
    std::string serialNumber() const;

    void setCardInfo(const std::vector<std::pair<std::string, std::string>> &infos);

    QString displaySerialNumber() const;
    void setDisplaySerialNumber(const QString &sn);

    std::string appName() const;
    QString displayAppName() const;

    void setAppVersion(int version);
    int appVersion() const;
    QString displayAppVersion() const;

    void setManufacturer(const std::string &manufacturer);
    std::string manufacturer() const;

    std::string cardType() const;

    int cardVersion() const;
    QString displayCardVersion() const;

    QString cardHolder() const;
    QString publicKeyUrl() const;

    void setSigningKeyRef(const std::string &keyRef);
    std::string signingKeyRef() const;
    bool hasSigningKey() const;

    void setEncryptionKeyRef(const std::string &keyRef);
    std::string encryptionKeyRef() const;
    bool hasEncryptionKey() const;

    void setAuthenticationKeyRef(const std::string &keyRef);
    std::string authenticationKeyRef() const;
    bool hasAuthenticationKey() const;

    std::vector<PinState> pinStates() const;
    void setPinStates(const std::vector<PinState> &pinStates);

    bool hasNKSNullPin() const;
    bool hasSigGNullPin() const;

    std::string certificateData(const std::string &keyRef) const;
    void setCertificateData(const std::string &keyRef, const std::string &data);

    QString errorMsg() const;
    void setErrorMsg(const QString &msg);

    const std::vector<KeyPairInfo> &keyInfos() const;
    const KeyPairInfo &keyInfo(const std::string &keyRef) const;

    std::string keyFingerprint(const std::string &keyRef) const;

protected:
    void setAppType(AppType app);
    void setAppName(const std::string &name);
    void setDisplayAppName(const QString &displayAppName);
    void setInitialKeyInfos(const std::vector<KeyPairInfo> &infos);

    void addCardInfo(const std::string &name, const std::string &value);
    std::string cardInfo(const std::string &name) const;

private:
    void parseCardInfo(const std::string &name, const std::string &value);

    void updateKeyInfo(const KeyPairInfo &keyPairInfo);

private:
    AppType mAppType = AppType::NoApp;
    Status mStatus = NoCard;
    std::string mSerialNumber;
    QString mDisplaySerialNumber;
    std::string mAppName;
    int mAppVersion = -1;
    std::string mCardType;
    int mCardVersion = -1;
    QString mCardHolder;
    std::string mSigningKeyRef;
    std::string mEncryptionKeyRef;
    std::string mAuthenticationKeyRef;
    std::vector<PinState> mPinStates;
    QString mErrMsg;
    std::vector<KeyPairInfo> mKeyInfos;
    std::multimap<std::string, std::string> mCardInfo;
    QString mDisplayAppName;
};
} // namespace Smartcard
} // namespace Kleopatra
