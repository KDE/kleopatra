/* -*- mode: c++; c-basic-offset:4 -*-
    smartcard/readerstatus.cpp

    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2009 Klarälvdalens Datakonsult AB
    SPDX-FileCopyrightText: 2020 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include <config-kleopatra.h>

#include "readerstatus.h"

#include "deviceinfowatcher.h"

#include <utils/qt-cxx20-compat.h>

#include <Libkleo/Algorithm>
#include <Libkleo/Assuan>
#include <Libkleo/FileSystemWatcher>
#include <Libkleo/Formatting>
#include <Libkleo/GnuPG>
#include <Libkleo/KeyCache>
#include <Libkleo/Stl_Util>

#include <QGpgME/Debug>

#include <gpgme++/context.h>
#include <gpgme++/defaultassuantransaction.h>
#include <gpgme++/engineinfo.h>

#include <gpg-error.h>

#include "netkeycard.h"
#include "openpgpcard.h"
#include "p15card.h"
#include "pivcard.h"

#include <QMutex>
#include <QPointer>
#include <QProcess>
#include <QRegularExpression>
#include <QThread>
#include <QWaitCondition>

#include "utils/kdtoolsglobal.h"

#include "kleopatra_debug.h"

using namespace Kleo;
using namespace Kleo::SmartCard;
using namespace GpgME;

static ReaderStatus *self = nullptr;

#define xtoi_1(p) (*(p) <= '9' ? (*(p) - '0') : *(p) <= 'F' ? (*(p) - 'A' + 10) : (*(p) - 'a' + 10))
#define xtoi_2(p) ((xtoi_1(p) * 16) + xtoi_1((p) + 1))

Q_DECLARE_METATYPE(GpgME::Error)
Q_DECLARE_METATYPE(GpgME::Protocol)

namespace
{
static bool gpgHasMultiCardMultiAppSupport()
{
    return !(engineInfo(GpgME::GpgEngine).engineVersion() < "2.3.0");
}

static QDebug operator<<(QDebug s, const std::vector<std::pair<std::string, std::string>> &v)
{
    using pair = std::pair<std::string, std::string>;
    s << '(';
    for (const pair &p : v) {
        s << "status(" << QString::fromStdString(p.first) << ") =" << QString::fromStdString(p.second) << '\n';
    }
    return s << ')';
}

struct CardApp {
    std::string serialNumber;
    std::string appName;
};

static void
logUnexpectedStatusLine(const std::pair<std::string, std::string> &line, const std::string &prefix = std::string(), const std::string &command = std::string())
{
    qCWarning(KLEOPATRA_LOG) << (!prefix.empty() ? QString::fromStdString(prefix + ": ") : QString()) << "Unexpected status line"
                             << (!command.empty() ? QString::fromStdString(" on " + command + ":") : QLatin1String(":")) << QString::fromStdString(line.first)
                             << QString::fromStdString(line.second);
}

static int parse_app_version(const std::string &s)
{
    return std::atoi(s.c_str());
}

static Card::PinState parse_pin_state(const QString &s)
{
    bool ok;
    int i = s.toInt(&ok);
    if (!ok) {
        qCDebug(KLEOPATRA_LOG) << "Failed to parse pin state" << s;
        return Card::UnknownPinState;
    }
    switch (i) {
    case -4:
        return Card::NullPin;
    case -3:
        return Card::PinBlocked;
    case -2:
        return Card::NoPin;
    case -1:
        return Card::UnknownPinState;
    default:
        if (i < 0) {
            return Card::UnknownPinState;
        } else {
            return Card::PinOk;
        }
    }
}

static const std::string scd_getattr_status(std::shared_ptr<Context> &gpgAgent, const char *what, Error &err)
{
    std::string cmd = "SCD GETATTR ";
    cmd += what;
    return Assuan::sendStatusCommand(gpgAgent, cmd.c_str(), err);
}

static const std::string getAttribute(std::shared_ptr<Context> &gpgAgent, const char *attribute, const char *versionHint)
{
    Error err;
    const auto result = scd_getattr_status(gpgAgent, attribute, err);
    if (err) {
        if (err.code() == GPG_ERR_INV_NAME) {
            qCDebug(KLEOPATRA_LOG) << "Querying for attribute" << attribute << "not yet supported; needs GnuPG" << versionHint;
        } else {
            qCWarning(KLEOPATRA_LOG) << "Running SCD GETATTR " << attribute << " failed:" << err;
        }
        return std::string();
    }
    return result;
}

enum GetCardsAndAppsOptions {
    WithReportedAppOrder,
    WithStableAppOrder,
};

static std::vector<CardApp> getCardsAndApps(std::shared_ptr<Context> &gpgAgent, GetCardsAndAppsOptions options, Error &err)
{
    std::vector<CardApp> result;
    if (gpgHasMultiCardMultiAppSupport()) {
        const std::string command = "SCD GETINFO all_active_apps";
        const auto statusLines = Assuan::sendStatusLinesCommand(gpgAgent, command.c_str(), err);
        if (err) {
            return result;
        }
        for (const auto &statusLine : statusLines) {
            if (statusLine.first == "SERIALNO") {
                const auto serialNumberAndApps = QByteArray::fromStdString(statusLine.second).split(' ');
                if (serialNumberAndApps.size() >= 2) {
                    const auto serialNumber = serialNumberAndApps[0];
                    auto apps = serialNumberAndApps.mid(1);
                    if (options == WithStableAppOrder) {
                        // sort the apps to get a stable order independently of the currently selected application
                        std::sort(apps.begin(), apps.end());
                    }
                    for (const auto &app : apps) {
                        qCDebug(KLEOPATRA_LOG) << "getCardsAndApps(): Found card" << serialNumber << "with app" << app;
                        result.push_back({serialNumber.toStdString(), app.toStdString()});
                    }
                } else {
                    logUnexpectedStatusLine(statusLine, "getCardsAndApps()", command);
                }
            } else {
                logUnexpectedStatusLine(statusLine, "getCardsAndApps()", command);
            }
        }
    } else {
        // use SCD SERIALNO to get the currently active card
        const auto serialNumber = Assuan::sendStatusCommand(gpgAgent, "SCD SERIALNO", err);
        if (err) {
            return result;
        }
        // use SCD GETATTR APPTYPE to find out which app is active
        auto appName = scd_getattr_status(gpgAgent, "APPTYPE", err);
        std::transform(appName.begin(), appName.end(), appName.begin(), [](unsigned char c) {
            return std::tolower(c);
        });
        if (err) {
            return result;
        }
        result.push_back({serialNumber, appName});
    }
    return result;
}

static std::string switchCard(std::shared_ptr<Context> &gpgAgent, const std::string &serialNumber, Error &err)
{
    const std::string command = "SCD SWITCHCARD " + serialNumber;
    const auto statusLines = Assuan::sendStatusLinesCommand(gpgAgent, command.c_str(), err);
    if (err) {
        return std::string();
    }
    if (statusLines.size() == 1 && statusLines[0].first == "SERIALNO" && statusLines[0].second == serialNumber) {
        return serialNumber;
    }
    qCWarning(KLEOPATRA_LOG) << "switchCard():" << command << "returned" << statusLines << "(expected:"
                             << "SERIALNO " + serialNumber << ")";
    return std::string();
}

static std::string switchApp(std::shared_ptr<Context> &gpgAgent, const std::string &serialNumber, const std::string &appName, Error &err)
{
    const std::string command = "SCD SWITCHAPP " + appName;
    const auto statusLines = Assuan::sendStatusLinesCommand(gpgAgent, command.c_str(), err);
    if (err) {
        return std::string();
    }
    if (statusLines.size() == 1 && statusLines[0].first == "SERIALNO" && statusLines[0].second.find(serialNumber + ' ' + appName) == 0) {
        return appName;
    }
    qCWarning(KLEOPATRA_LOG) << "switchApp():" << command << "returned" << statusLines << "(expected:"
                             << "SERIALNO " + serialNumber + ' ' + appName + "..."
                             << ")";
    return std::string();
}

static std::vector<std::string> getCardApps(std::shared_ptr<Context> &gpgAgent, const std::string &serialNumber, Error &err)
{
    const auto cardApps = getCardsAndApps(gpgAgent, WithReportedAppOrder, err);
    if (err) {
        return {};
    }
    std::vector<std::string> apps;
    kdtools::transform_if(
        cardApps.begin(),
        cardApps.end(),
        std::back_inserter(apps),
        [](const auto &cardApp) {
            return cardApp.appName;
        },
        [serialNumber](const auto &cardApp) {
            return cardApp.serialNumber == serialNumber;
        });
    qCDebug(KLEOPATRA_LOG) << __func__ << "apps:" << apps;
    return apps;
}

static void switchCardBackToOpenPGPApp(std::shared_ptr<Context> &gpgAgent, const std::string &serialNumber, Error &err)
{
    if (!gpgHasMultiCardMultiAppSupport()) {
        return;
    }
    const auto apps = getCardApps(gpgAgent, serialNumber, err);
    if (err || apps.empty() || apps[0] == OpenPGPCard::AppName) {
        return;
    }
    if (Kleo::contains(apps, OpenPGPCard::AppName)) {
        switchApp(gpgAgent, serialNumber, OpenPGPCard::AppName, err);
    }
}

static const char *get_openpgp_card_manufacturer_from_serial_number(const std::string &serialno)
{
    qCDebug(KLEOPATRA_LOG) << "get_openpgp_card_manufacturer_from_serial_number(" << serialno.c_str() << ")";

    const bool isProperOpenPGPCardSerialNumber = serialno.size() == 32 && serialno.substr(0, 12) == "D27600012401";
    if (isProperOpenPGPCardSerialNumber) {
        const char *sn = serialno.c_str();
        const int manufacturerId = xtoi_2(sn + 16) * 256 + xtoi_2(sn + 18);
        switch (manufacturerId) {
        case 0x0001:
            return "PPC Card Systems";
        case 0x0002:
            return "Prism";
        case 0x0003:
            return "OpenFortress";
        case 0x0004:
            return "Wewid";
        case 0x0005:
            return "ZeitControl";
        case 0x0006:
            return "Yubico";
        case 0x0007:
            return "OpenKMS";
        case 0x0008:
            return "LogoEmail";

        case 0x002A:
            return "Magrathea";

        case 0x1337:
            return "Warsaw Hackerspace";

        case 0xF517:
            return "FSIJ";

        /* 0x0000 and 0xFFFF are defined as test cards per spec,
           0xFF00 to 0xFFFE are assigned for use with randomly created
           serial numbers.  */
        case 0x0000:
        case 0xffff:
            return "test card";
        default:
            return (manufacturerId & 0xff00) == 0xff00 ? "unmanaged S/N range" : "unknown";
        }
    } else {
        return "unknown";
    }
}

static std::vector<std::string> get_openpgp_card_supported_algorithms_announced_by_card(std::shared_ptr<Context> &gpgAgent)
{
    static constexpr std::string_view cardSlotPrefix = "OPENPGP.1 ";
    static const std::map<std::string_view, std::string_view> algoMapping = {
        {"cv25519", "curve25519"},
        {"cv448", "curve448"},
        {"ed25519", "curve25519"},
        {"ed448", "curve448"},
        {"x448", "curve448"},
    };

    Error err;
    const auto lines = Assuan::sendStatusLinesCommand(gpgAgent, "SCD GETATTR KEY-ATTR-INFO", err);
    if (err) {
        return {};
    }

    std::vector<std::string> algos;
    kdtools::transform_if(
        lines.cbegin(),
        lines.cend(),
        std::back_inserter(algos),
        [](const auto &line) {
            auto algo = line.second.substr(cardSlotPrefix.size());
            // map a few algorithms to the standard names used by us
            const auto mapping = algoMapping.find(algo);
            if (mapping != algoMapping.end()) {
                algo = mapping->second;
            }
            return algo;
        },
        [](const auto &line) {
            // only consider KEY-ATTR-INFO status lines for the first card slot;
            // for now, we assume that all card slots support the same algorithms
            return line.first == "KEY-ATTR-INFO" && line.second.starts_with(cardSlotPrefix);
        });
    // remove duplicate algorithms
    std::sort(algos.begin(), algos.end());
    algos.erase(std::unique(algos.begin(), algos.end()), algos.end());
    qCDebug(KLEOPATRA_LOG) << __func__ << "returns" << algos;
    return algos;
}

static std::vector<std::string> get_openpgp_card_supported_algorithms(Card *card, std::shared_ptr<Context> &gpgAgent)
{
    // first ask the smart card for the supported algorithms
    const std::vector<std::string> announcedAlgos = get_openpgp_card_supported_algorithms_announced_by_card(gpgAgent);
    if (!announcedAlgos.empty()) {
        return announcedAlgos;
    }

    // otherwise, fall back to hard-coded lists
    if ((card->cardType() == "yubikey") && (card->cardVersion() >= 0x050203)) {
        return {
            "rsa2048",
            "rsa3072",
            "rsa4096",
            "brainpoolP256r1",
            "brainpoolP384r1",
            "brainpoolP512r1",
            "curve25519",
        };
    } else if ((card->cardType() == "zeitcontrol") && (card->appVersion() >= 0x0304)) {
        return {
            "rsa2048",
            "rsa3072",
            "rsa4096",
            "brainpoolP256r1",
            "brainpoolP384r1",
            "brainpoolP512r1",
        };
    }
    return {"rsa2048", "rsa3072", "rsa4096"};
}

static bool isOpenPGPCardSerialNumber(const std::string &serialNumber)
{
    return serialNumber.size() == 32 && serialNumber.substr(0, 12) == "D27600012401";
}

static const std::string getDisplaySerialNumber(std::shared_ptr<Context> &gpgAgent, Error &err)
{
    const auto displaySerialNumber = scd_getattr_status(gpgAgent, "$DISPSERIALNO", err);
    if (err && err.code() != GPG_ERR_INV_NAME) {
        qCWarning(KLEOPATRA_LOG) << "Running SCD GETATTR $DISPSERIALNO failed:" << err;
    }
    return displaySerialNumber;
}

static void setDisplaySerialNumber(Card *card, std::shared_ptr<Context> &gpgAgent)
{
    static const QRegularExpression leadingZeros(QStringLiteral("^0*"));

    Error err;
    const QString displaySerialNumber = QString::fromStdString(getDisplaySerialNumber(gpgAgent, err));
    if (err) {
        card->setDisplaySerialNumber(QString::fromStdString(card->serialNumber()));
        return;
    }
    if (isOpenPGPCardSerialNumber(card->serialNumber()) && displaySerialNumber.size() == 12) {
        // add a space between manufacturer id and card id for OpenPGP cards
        card->setDisplaySerialNumber(displaySerialNumber.left(4) + QLatin1Char(' ') + displaySerialNumber.right(8));
    } else {
        card->setDisplaySerialNumber(displaySerialNumber);
    }
    return;
}

static void learnCardKeyStubs(const Card *card, std::shared_ptr<Context> &gpg_agent)
{
    for (const KeyPairInfo &keyInfo : card->keyInfos()) {
        if (!keyInfo.grip.empty()) {
            Error err;
            const auto command = std::string("READKEY --card --no-data -- ") + keyInfo.keyRef;
            (void)Assuan::sendStatusLinesCommand(gpg_agent, command.c_str(), err);
            if (err) {
                qCWarning(KLEOPATRA_LOG) << "Running" << command << "failed:" << err;
            }
        }
    }
}

static void handle_openpgp_card(std::shared_ptr<Card> &ci, std::shared_ptr<Context> &gpg_agent)
{
    Error err;
    auto pgpCard = new OpenPGPCard(*ci);

    const auto info = Assuan::sendStatusLinesCommand(gpg_agent, "SCD LEARN --force", err);
    if (err.code()) {
        ci->setStatus(Card::CardError);
        return;
    }
    pgpCard->setCardInfo(info);

    if (pgpCard->manufacturer().empty()) {
        // fallback in case MANUFACTURER is not yet included in the card info
        pgpCard->setManufacturer(get_openpgp_card_manufacturer_from_serial_number(ci->serialNumber()));
    }

    setDisplaySerialNumber(pgpCard, gpg_agent);

    learnCardKeyStubs(pgpCard, gpg_agent);

    pgpCard->setSupportedAlgorithms(get_openpgp_card_supported_algorithms(pgpCard, gpg_agent));

    ci.reset(pgpCard);
}

static void readKeyPairInfoFromPIVCard(const std::string &keyRef, PIVCard *pivCard, const std::shared_ptr<Context> &gpg_agent)
{
    Error err;
    const std::string command = std::string("SCD READKEY --info-only -- ") + keyRef;
    const auto keyPairInfoLines = Assuan::sendStatusLinesCommand(gpg_agent, command.c_str(), err);
    if (err) {
        qCWarning(KLEOPATRA_LOG) << "Running" << command << "failed:" << err;
        return;
    }
    // this adds the key algorithm (and the key creation date, but that seems to be unset for PIV) to the existing key pair information
    pivCard->setCardInfo(keyPairInfoLines);
}

static void readCertificateFromPIVCard(const std::string &keyRef, PIVCard *pivCard, const std::shared_ptr<Context> &gpg_agent)
{
    Error err;
    const std::string command = std::string("SCD READCERT ") + keyRef;
    const std::string certificateData = Assuan::sendDataCommand(gpg_agent, command.c_str(), err);
    if (err && err.code() != GPG_ERR_NOT_FOUND) {
        qCWarning(KLEOPATRA_LOG) << "Running" << command << "failed:" << err;
        return;
    }
    if (certificateData.empty()) {
        qCDebug(KLEOPATRA_LOG) << "readCertificateFromPIVCard(" << QString::fromStdString(keyRef) << "): No certificate stored on card";
        return;
    }
    qCDebug(KLEOPATRA_LOG) << "readCertificateFromPIVCard(" << QString::fromStdString(keyRef) << "): Found certificate stored on card";
    pivCard->setCertificateData(keyRef, certificateData);
}

static void handle_piv_card(std::shared_ptr<Card> &ci, std::shared_ptr<Context> &gpg_agent)
{
    Error err;
    auto pivCard = new PIVCard(*ci);

    const auto info = Assuan::sendStatusLinesCommand(gpg_agent, "SCD LEARN --force", err);
    if (err) {
        ci->setStatus(Card::CardError);
        return;
    }
    pivCard->setCardInfo(info);

    setDisplaySerialNumber(pivCard, gpg_agent);

    for (const KeyPairInfo &keyInfo : pivCard->keyInfos()) {
        if (!keyInfo.grip.empty()) {
            readKeyPairInfoFromPIVCard(keyInfo.keyRef, pivCard, gpg_agent);
            readCertificateFromPIVCard(keyInfo.keyRef, pivCard, gpg_agent);
        }
    }

    learnCardKeyStubs(pivCard, gpg_agent);

    ci.reset(pivCard);
}

static void handle_p15_card(std::shared_ptr<Card> &ci, std::shared_ptr<Context> &gpg_agent)
{
    Error err;
    auto p15Card = new P15Card(*ci);

    auto info = Assuan::sendStatusLinesCommand(gpg_agent, "SCD LEARN --force", err);
    if (err) {
        ci->setStatus(Card::CardError);
        return;
    }
    const auto fprs = Assuan::sendStatusLinesCommand(gpg_agent, "SCD GETATTR KEY-FPR", err);
    if (!err) {
        info.insert(info.end(), fprs.begin(), fprs.end());
    }

    p15Card->setCardInfo(info);

    learnCardKeyStubs(p15Card, gpg_agent);

    setDisplaySerialNumber(p15Card, gpg_agent);

    ci.reset(p15Card);
}

static void handle_netkey_card(std::shared_ptr<Card> &ci, std::shared_ptr<Context> &gpg_agent)
{
    Error err;
    auto nkCard = new NetKeyCard(*ci);
    ci.reset(nkCard);

    ci->setAppVersion(parse_app_version(scd_getattr_status(gpg_agent, "NKS-VERSION", err)));

    if (err.code()) {
        qCWarning(KLEOPATRA_LOG) << "Running SCD GETATTR NKS-VERSION failed:" << err;
        ci->setErrorMsg(QStringLiteral("NKS-VERSION failed: ") + Formatting::errorAsString(err));
        return;
    }

    if (ci->appVersion() < 3) {
        qCDebug(KLEOPATRA_LOG) << "not a NetKey v3 (or later) card, giving up. Version:" << ci->appVersion();
        ci->setErrorMsg(QStringLiteral("NetKey v%1 cards are not supported.").arg(ci->appVersion()));
        return;
    }

    setDisplaySerialNumber(nkCard, gpg_agent);

    // the following only works for NKS v3...
    const auto chvStatus = QString::fromStdString(scd_getattr_status(gpg_agent, "CHV-STATUS", err)).split(QLatin1Char(' '));
    if (err.code()) {
        qCDebug(KLEOPATRA_LOG) << "Running SCD GETATTR CHV-STATUS failed:" << err;
        ci->setErrorMsg(QStringLiteral("CHV-Status failed: ") + Formatting::errorAsString(err));
        return;
    }

    std::vector<Card::PinState> states;
    states.reserve(chvStatus.count());
    // CHV Status for NKS v3 is
    // Pin1 (Normal pin) Pin2 (Normal PUK)
    // SigG1 SigG PUK.
    int num = 0;
    for (const auto &state : chvStatus) {
        const auto parsed = parse_pin_state(state);
        states.push_back(parsed);
        if (parsed == Card::NullPin) {
            if (num == 0) {
                ci->setHasNullPin(true);
            }
        }
        ++num;
    }
    nkCard->setPinStates(states);

    const auto info = Assuan::sendStatusLinesCommand(gpg_agent, "SCD LEARN --force", err);
    if (err) {
        ci->setStatus(Card::CardError);
        return;
    }
    nkCard->setCardInfo(info);

    learnCardKeyStubs(nkCard, gpg_agent);
}

static std::shared_ptr<Card> get_card_status(const std::string &serialNumber, const std::string &appName, std::shared_ptr<Context> &gpg_agent)
{
    qCDebug(KLEOPATRA_LOG) << "get_card_status(" << serialNumber << ',' << appName << ',' << gpg_agent.get() << ')';
    auto ci = std::shared_ptr<Card>(new Card());

    if (gpgHasMultiCardMultiAppSupport()) {
        // select card
        Error err;
        const auto result = switchCard(gpg_agent, serialNumber, err);
        if (err) {
            if (err.code() == GPG_ERR_CARD_NOT_PRESENT || err.code() == GPG_ERR_CARD_REMOVED) {
                ci->setStatus(Card::NoCard);
            } else {
                ci->setStatus(Card::CardError);
            }
            return ci;
        }
        if (result.empty()) {
            qCWarning(KLEOPATRA_LOG) << "get_card_status: switching card failed";
            ci->setStatus(Card::CardError);
            return ci;
        }
        ci->setStatus(Card::CardPresent);
    } else {
        ci->setStatus(Card::CardPresent);
    }

    if (gpgHasMultiCardMultiAppSupport()) {
        // select app
        Error err;
        const auto result = switchApp(gpg_agent, serialNumber, appName, err);
        if (err) {
            if (err.code() == GPG_ERR_CARD_NOT_PRESENT || err.code() == GPG_ERR_CARD_REMOVED) {
                ci->setStatus(Card::NoCard);
            } else {
                ci->setStatus(Card::CardError);
            }
            return ci;
        }
        if (result.empty()) {
            qCWarning(KLEOPATRA_LOG) << "get_card_status: switching app failed";
            ci->setStatus(Card::CardError);
            return ci;
        }
    }

    ci->setSerialNumber(serialNumber);

    ci->setSigningKeyRef(getAttribute(gpg_agent, "$SIGNKEYID", "2.2.18"));
    ci->setEncryptionKeyRef(getAttribute(gpg_agent, "$ENCRKEYID", "2.2.18"));

    // Handle different card types
    if (appName == NetKeyCard::AppName) {
        qCDebug(KLEOPATRA_LOG) << "get_card_status: found Netkey card" << ci->serialNumber().c_str() << "end";
        handle_netkey_card(ci, gpg_agent);
    } else if (appName == OpenPGPCard::AppName) {
        qCDebug(KLEOPATRA_LOG) << "get_card_status: found OpenPGP card" << ci->serialNumber().c_str() << "end";
        ci->setAuthenticationKeyRef(OpenPGPCard::pgpAuthKeyRef());
        handle_openpgp_card(ci, gpg_agent);
    } else if (appName == PIVCard::AppName) {
        qCDebug(KLEOPATRA_LOG) << "get_card_status: found PIV card" << ci->serialNumber().c_str() << "end";
        handle_piv_card(ci, gpg_agent);
    } else if (appName == P15Card::AppName) {
        qCDebug(KLEOPATRA_LOG) << "get_card_status: found P15 card" << ci->serialNumber().c_str() << "end";
        handle_p15_card(ci, gpg_agent);
    } else {
        qCDebug(KLEOPATRA_LOG) << "get_card_status: unhandled application:" << appName;
    }

    if (gpgHasMultiCardMultiAppSupport() && appName != OpenPGPCard::AppName) {
        // switch the card app back to OpenPGP; errors are ignored
        GpgME::Error dummy;
        switchCardBackToOpenPGPApp(gpg_agent, serialNumber, dummy);
    }

    return ci;
}

static bool isCardNotPresentError(const GpgME::Error &err)
{
    // see fixup_scd_errors() in gpg-card.c
    return err
        && ((err.code() == GPG_ERR_CARD_NOT_PRESENT)
            || ((err.code() == GPG_ERR_ENODEV || err.code() == GPG_ERR_CARD_REMOVED) && (err.sourceID() == GPG_ERR_SOURCE_SCD)));
}

static std::vector<std::shared_ptr<Card>> update_cardinfo(std::shared_ptr<Context> &gpgAgent)
{
    qCDebug(KLEOPATRA_LOG) << "update_cardinfo()";

    // ensure that a card is present and that all cards are properly set up
    {
        Error err;
        const char *command = (gpgHasMultiCardMultiAppSupport()) ? "SCD SERIALNO --all" : "SCD SERIALNO";
        const std::string serialno = Assuan::sendStatusCommand(gpgAgent, command, err);
        if (err) {
            if (isCardNotPresentError(err)) {
                qCDebug(KLEOPATRA_LOG) << "update_cardinfo: No card present";
                return std::vector<std::shared_ptr<Card>>();
            } else {
                qCWarning(KLEOPATRA_LOG) << "Running" << command << "failed:" << err;
                auto ci = std::shared_ptr<Card>(new Card());
                ci->setStatus(Card::CardError);
                return std::vector<std::shared_ptr<Card>>(1, ci);
            }
        }
    }

    Error err;
    const std::vector<CardApp> cardApps = getCardsAndApps(gpgAgent, WithStableAppOrder, err);
    if (err) {
        if (isCardNotPresentError(err)) {
            qCDebug(KLEOPATRA_LOG) << "update_cardinfo: No card present";
            return std::vector<std::shared_ptr<Card>>();
        } else {
            qCWarning(KLEOPATRA_LOG) << "Getting active apps on all inserted cards failed:" << err;
            auto ci = std::shared_ptr<Card>(new Card());
            ci->setStatus(Card::CardError);
            return std::vector<std::shared_ptr<Card>>(1, ci);
        }
    }

    std::vector<std::shared_ptr<Card>> cards;
    for (const auto &cardApp : cardApps) {
        const auto card = get_card_status(cardApp.serialNumber, cardApp.appName, gpgAgent);
        cards.push_back(card);
    }
    return cards;
}
} // namespace

struct Transaction {
    CardApp cardApp;
    QByteArray command;
    QPointer<QObject> receiver;
    ReaderStatus::TransactionFunc slot;
    AssuanTransaction *assuanTransaction;
};

static const Transaction learnCMSTransaction = {{"__all__", "__cms__"}, "__learn__", nullptr, nullptr, nullptr};
static const Transaction updateTransaction = {{"__all__", "__all__"}, "__update__", nullptr, nullptr, nullptr};
static const Transaction quitTransaction = {{"__all__", "__all__"}, "__quit__", nullptr, nullptr, nullptr};

namespace
{
static void logProcessOutput(const char *prefix, const char *label, const QByteArray &output)
{
    if (output.isEmpty()) {
        return;
    }
    for (const auto &line : output.split('\n')) {
        qCDebug(KLEOPATRA_LOG) << prefix << label << line;
    }
}

class ReaderStatusThread : public QThread
{
    Q_OBJECT
public:
    explicit ReaderStatusThread(QObject *parent = nullptr)
        : QThread(parent)
        , m_transactions(1, updateTransaction) // force initial scan
    {
        connect(this, &ReaderStatusThread::oneTransactionFinished, this, &ReaderStatusThread::slotOneTransactionFinished);
    }

    std::vector<std::shared_ptr<Card>> cardInfos() const
    {
        const QMutexLocker locker(&m_mutex);
        return m_cardInfos;
    }

    Card::Status cardStatus(unsigned int slot) const
    {
        const QMutexLocker locker(&m_mutex);
        if (slot < m_cardInfos.size()) {
            return m_cardInfos[slot]->status();
        } else {
            return Card::NoCard;
        }
    }

    void addTransaction(const Transaction &t)
    {
        const QMutexLocker locker(&m_mutex);
        m_transactions.push_back(t);
        m_waitForTransactions.wakeOne();
    }

Q_SIGNALS:
    void firstCardWithNullPinChanged(const std::string &serialNumber);
    void cardAdded(const std::string &serialNumber, const std::string &appName);
    void cardChanged(const std::string &serialNumber, const std::string &appName);
    void cardRemoved(const std::string &serialNumber, const std::string &appName);
    void updateCardsStarted();
    void updateCardStarted(const std::string &serialNumber, const std::string &appName);
    void updateFinished();
    void oneTransactionFinished(const GpgME::Error &err);
    void startingLearnCards(GpgME::Protocol protocol);
    void cardsLearned(GpgME::Protocol protocol);

public Q_SLOTS:
    void deviceStatusChanged(const QByteArray &details)
    {
        qCDebug(KLEOPATRA_LOG) << "ReaderStatusThread[GUI]::deviceStatusChanged(" << details << ")";
        addTransaction(updateTransaction);
    }

    void ping()
    {
        qCDebug(KLEOPATRA_LOG) << "ReaderStatusThread[GUI]::ping()";
        addTransaction(updateTransaction);
    }

    void learnCardsCMS()
    {
        qCDebug(KLEOPATRA_LOG) << "ReaderStatusThread[GUI]::learnCardsCMS()";
        addTransaction(learnCMSTransaction);
    }

    void stop()
    {
        const QMutexLocker locker(&m_mutex);
        m_transactions.push_front(quitTransaction);
        m_waitForTransactions.wakeOne();
    }

private Q_SLOTS:
    void slotOneTransactionFinished(const GpgME::Error &err)
    {
        std::list<Transaction> ft;
        KDAB_SYNCHRONIZED(m_mutex)
        ft.splice(ft.begin(), m_finishedTransactions);
        for (const Transaction &t : std::as_const(ft))
            if (t.receiver && t.slot) {
                QMetaObject::invokeMethod(
                    t.receiver,
                    [&t, &err]() {
                        t.slot(err);
                    },
                    Qt::DirectConnection);
            }
    }

private:
    void learnCMSCards()
    {
        QProcess process;
        connect(&process, &QProcess::readyReadStandardOutput, &process, [&process]() {
            logProcessOutput("learnCMSCards", "stdout:", process.readAllStandardOutput());
        });
        connect(&process, &QProcess::readyReadStandardError, &process, [&process]() {
            logProcessOutput("learnCMSCards", "stderr:", process.readAllStandardError());
        });

        process.start(gpgSmPath(), {QStringLiteral("--learn-card"), QStringLiteral("-v")});
        qCDebug(KLEOPATRA_LOG) << __func__ << "Running" << process.program() << process.arguments().join(QLatin1Char{' '});
        if (!process.waitForStarted()) {
            qCDebug(KLEOPATRA_LOG) << __func__ << "Starting" << process.program() << "failed";
            return;
        }
        // ensure that gpgsm doesn't wait for input
        process.closeWriteChannel();

        const bool success = process.waitForFinished(60000); // 60 seconds should be more than enough

        logProcessOutput(__func__, "stdout:", process.readAllStandardOutput());
        logProcessOutput(__func__, "stderr:", process.readAllStandardError());
        if (success) {
            qCDebug(KLEOPATRA_LOG) << __func__ << "Running" << process.program() << process.arguments().join(QLatin1Char{' '}) << "succeeded";
        } else {
            qCDebug(KLEOPATRA_LOG) << __func__ << "Running" << process.program() << process.arguments().join(QLatin1Char{' '})
                                   << "failed; error:" << process.error() << ", exit code:" << process.exitCode();
        }
    }

    void run() override
    {
        while (true) {
            std::shared_ptr<Context> gpgAgent;

            CardApp cardApp;
            QByteArray command;
            bool nullSlot = false;
            AssuanTransaction *assuanTransaction = nullptr;
            std::list<Transaction> item;
            std::vector<std::shared_ptr<Card>> oldCards;

            while (!KeyCache::instance()->initialized()) {
                qCDebug(KLEOPATRA_LOG) << "Waiting for Keycache to be initialized.";
                sleep(1);
            }

            Error err;
            std::unique_ptr<Context> c = Context::createForEngine(AssuanEngine, &err);
            if (err.code() == GPG_ERR_NOT_SUPPORTED) {
                return;
            }
            gpgAgent = std::shared_ptr<Context>(c.release());

            KDAB_SYNCHRONIZED(m_mutex)
            {
                while (m_transactions.empty()) {
                    // go to sleep waiting for more work:
                    qCDebug(KLEOPATRA_LOG) << "ReaderStatusThread[2nd]: waiting for commands";
                    m_waitForTransactions.wait(&m_mutex);
                }

                // splice off the first transaction without
                // copying, so we own it without really importing
                // it into this thread (the QPointer isn't
                // thread-safe):
                item.splice(item.end(), m_transactions, m_transactions.begin());

                // make local copies of the interesting stuff so
                // we can release the mutex again:
                cardApp = item.front().cardApp;
                command = item.front().command;
                nullSlot = !item.front().slot;
                // we take ownership of the assuan transaction
                std::swap(assuanTransaction, item.front().assuanTransaction);
                oldCards = m_cardInfos;
            }

            qCDebug(KLEOPATRA_LOG) << "ReaderStatusThread[2nd]: new iteration command=" << command << " ; nullSlot=" << nullSlot;
            // now, let's see what we got:
            if (nullSlot && command == quitTransaction.command) {
                return; // quit
            }

            if (nullSlot && command == updateTransaction.command) {
                bool anyError = false;

                if (cardApp.serialNumber == "__all__" || cardApp.appName == "__all__") {
                    Q_EMIT updateCardsStarted();
                    std::vector<std::shared_ptr<Card>> newCards = update_cardinfo(gpgAgent);

                    KDAB_SYNCHRONIZED(m_mutex)
                    {
                        m_cardInfos = newCards;
                    }

                    std::string firstCardWithNullPin;
                    for (const auto &newCard : newCards) {
                        const auto serialNumber = newCard->serialNumber();
                        const auto appName = newCard->appName();
                        const auto matchingOldCard =
                            std::find_if(oldCards.cbegin(), oldCards.cend(), [serialNumber, appName](const std::shared_ptr<Card> &card) {
                                return card->serialNumber() == serialNumber && card->appName() == appName;
                            });
                        if (matchingOldCard == oldCards.cend()) {
                            qCDebug(KLEOPATRA_LOG) << "ReaderStatusThread: Card" << serialNumber << "with app" << appName << "was added";
                            Q_EMIT cardAdded(serialNumber, appName);
                        } else {
                            if (*newCard != **matchingOldCard) {
                                qCDebug(KLEOPATRA_LOG) << "ReaderStatusThread: Card" << serialNumber << "with app" << appName << "changed";
                                Q_EMIT cardChanged(serialNumber, appName);
                            }
                            oldCards.erase(matchingOldCard);
                        }
                        if (newCard->hasNullPin() && firstCardWithNullPin.empty()) {
                            firstCardWithNullPin = newCard->serialNumber();
                        }
                        if (newCard->status() == Card::CardError) {
                            anyError = true;
                        }
                    }
                    for (const auto &oldCard : oldCards) {
                        qCDebug(KLEOPATRA_LOG) << "ReaderStatusThread: Card" << oldCard->serialNumber() << "with app" << oldCard->appName() << "was removed";
                        Q_EMIT cardRemoved(oldCard->serialNumber(), oldCard->appName());
                    }

                    Q_EMIT firstCardWithNullPinChanged(firstCardWithNullPin);
                } else {
                    Q_EMIT updateCardStarted(cardApp.serialNumber, cardApp.appName);
                    auto updatedCard = get_card_status(cardApp.serialNumber, cardApp.appName, gpgAgent);
                    const auto serialNumber = updatedCard->serialNumber();
                    const auto appName = updatedCard->appName();

                    bool cardWasAdded = false;
                    bool cardWasChanged = false;
                    KDAB_SYNCHRONIZED(m_mutex)
                    {
                        const auto matchingCard = std::find_if(m_cardInfos.begin(), m_cardInfos.end(), [serialNumber, appName](const auto &card) {
                            return card->serialNumber() == serialNumber && card->appName() == appName;
                        });
                        if (matchingCard == m_cardInfos.end()) {
                            m_cardInfos.push_back(updatedCard);
                            cardWasAdded = true;
                        } else {
                            cardWasChanged = (*updatedCard != **matchingCard);
                            m_cardInfos[std::distance(m_cardInfos.begin(), matchingCard)] = updatedCard;
                        }
                        if (updatedCard->status() == Card::CardError) {
                            anyError = true;
                        }
                    }
                    if (cardWasAdded) {
                        qCDebug(KLEOPATRA_LOG) << "ReaderStatusThread: Card" << serialNumber << "with app" << appName << "was added";
                        Q_EMIT cardAdded(serialNumber, appName);
                    } else if (cardWasChanged) {
                        qCDebug(KLEOPATRA_LOG) << "ReaderStatusThread: Card" << serialNumber << "with app" << appName << "changed";
                        Q_EMIT cardChanged(serialNumber, appName);
                    }
                }

                if (anyError) {
                    gpgAgent.reset();
                }

                Q_EMIT updateFinished();
            } else if (nullSlot && command == learnCMSTransaction.command) {
                Q_EMIT startingLearnCards(GpgME::CMS);
                learnCMSCards();
                Q_EMIT cardsLearned(GpgME::CMS);
            } else {
                GpgME::Error err;
                if (gpgHasMultiCardMultiAppSupport()) {
                    switchCard(gpgAgent, cardApp.serialNumber, err);
                    if (!err) {
                        switchApp(gpgAgent, cardApp.serialNumber, cardApp.appName, err);
                    }
                }
                if (!err) {
                    if (assuanTransaction) {
                        (void)Assuan::sendCommand(gpgAgent, command.constData(), std::unique_ptr<AssuanTransaction>(assuanTransaction), err);
                    } else {
                        (void)Assuan::sendCommand(gpgAgent, command.constData(), err);
                    }
                }

                KDAB_SYNCHRONIZED(m_mutex)
                // splice 'item' into m_finishedTransactions:
                m_finishedTransactions.splice(m_finishedTransactions.end(), item);

                Q_EMIT oneTransactionFinished(err);
            }
        }
    }

private:
    mutable QMutex m_mutex;
    QWaitCondition m_waitForTransactions;
    // protected by m_mutex:
    std::vector<std::shared_ptr<Card>> m_cardInfos;
    std::list<Transaction> m_transactions, m_finishedTransactions;
};

}

class ReaderStatus::Private : ReaderStatusThread
{
    friend class Kleo::SmartCard::ReaderStatus;
    ReaderStatus *const q;

public:
    explicit Private(ReaderStatus *qq)
        : ReaderStatusThread(qq)
        , q(qq)
        , watcher()
    {
        Q_SET_OBJECT_NAME(watcher);

        qRegisterMetaType<Card::Status>("Kleo::SmartCard::Card::Status");
        qRegisterMetaType<GpgME::Error>("GpgME::Error");
        qRegisterMetaType<GpgME::Protocol>();

        connect(this, &::ReaderStatusThread::cardAdded, q, &ReaderStatus::cardAdded);
        connect(this, &::ReaderStatusThread::cardChanged, q, &ReaderStatus::cardChanged);
        connect(this, &::ReaderStatusThread::cardRemoved, q, &ReaderStatus::cardRemoved);
        connect(this, &::ReaderStatusThread::updateCardsStarted, q, &ReaderStatus::onUpdateCardsStarted);
        connect(this, &::ReaderStatusThread::updateCardStarted, q, &ReaderStatus::onUpdateCardStarted);
        connect(this, &::ReaderStatusThread::updateFinished, q, &ReaderStatus::onUpdateFinished);
        connect(this, &::ReaderStatusThread::firstCardWithNullPinChanged, q, &ReaderStatus::firstCardWithNullPinChanged);
        connect(this, &::ReaderStatusThread::startingLearnCards, q, &ReaderStatus::onStartingLearnCards);
        connect(this, &::ReaderStatusThread::cardsLearned, q, &ReaderStatus::onCardsLearned);

        if (DeviceInfoWatcher::isSupported()) {
            qCDebug(KLEOPATRA_LOG) << "ReaderStatus::Private: Using new DeviceInfoWatcher";
            connect(&devInfoWatcher, &DeviceInfoWatcher::statusChanged, this, &::ReaderStatusThread::deviceStatusChanged);
        } else {
            qCDebug(KLEOPATRA_LOG) << "ReaderStatus::Private: Using deprecated FileSystemWatcher";

            watcher.whitelistFiles(QStringList(QStringLiteral("reader_*.status")));
            watcher.addPath(Kleo::gnupgHomeDirectory());
            watcher.setDelay(100);

            connect(&watcher, &FileSystemWatcher::triggered, this, &::ReaderStatusThread::ping);
        }
    }
    ~Private() override
    {
        stop();
        if (!wait(100)) {
            terminate();
            wait();
        }
    }

private:
    std::string firstCardWithNullPinImpl() const
    {
        const auto cis = cardInfos();
        const auto firstWithNullPin = std::find_if(cis.cbegin(), cis.cend(), [](const std::shared_ptr<Card> &ci) {
            return ci->hasNullPin();
        });
        return firstWithNullPin != cis.cend() ? (*firstWithNullPin)->serialNumber() : std::string();
    }

private:
    FileSystemWatcher watcher;
    DeviceInfoWatcher devInfoWatcher;
    std::shared_ptr<KeyCacheAutoRefreshSuspension> keyCacheAutoRefreshSuspension;
    Action currentAction = NoAction;
    bool learnCMSTransactionScheduled = false;
};

ReaderStatus::ReaderStatus(QObject *parent)
    : QObject(parent)
    , d(new Private(this))
{
    self = this;

    qRegisterMetaType<std::string>("std::string");
}

ReaderStatus::~ReaderStatus()
{
    self = nullptr;
}

// slot
void ReaderStatus::startMonitoring()
{
    qCDebug(KLEOPATRA_LOG) << __func__;
    if (!KeyCache::instance()->initialized()) {
        qCDebug(KLEOPATRA_LOG) << __func__ << "waiting for key cache ...";
        connect(KeyCache::instance().get(), &KeyCache::keyListingDone, this, &ReaderStatus::startMonitoring);
        return;
    }
    disconnect(KeyCache::instance().get(), &KeyCache::keyListingDone, this, &ReaderStatus::startMonitoring);
    qCDebug(KLEOPATRA_LOG) << __func__ << "key cache is ready";
    d->start();
    if (DeviceInfoWatcher::isSupported()) {
        connect(&d->devInfoWatcher, &DeviceInfoWatcher::startOfGpgAgentRequested, this, &ReaderStatus::startOfGpgAgentRequested);
        d->devInfoWatcher.start();
    }
}

// static
ReaderStatus *ReaderStatus::mutableInstance()
{
    return self;
}

// static
const ReaderStatus *ReaderStatus::instance()
{
    return self;
}

ReaderStatus::Action ReaderStatus::currentAction() const
{
    return d->currentAction;
}

Card::Status ReaderStatus::cardStatus(unsigned int slot) const
{
    return d->cardStatus(slot);
}

std::string ReaderStatus::firstCardWithNullPin() const
{
    return d->firstCardWithNullPinImpl();
}

void ReaderStatus::startSimpleTransaction(const std::shared_ptr<Card> &card, const QByteArray &command, QObject *receiver, const TransactionFunc &slot)
{
    const CardApp cardApp = {card->serialNumber(), card->appName()};
    const Transaction t = {cardApp, command, receiver, slot, nullptr};
    d->addTransaction(t);
}

void ReaderStatus::startTransaction(const std::shared_ptr<Card> &card,
                                    const QByteArray &command,
                                    QObject *receiver,
                                    const TransactionFunc &slot,
                                    std::unique_ptr<AssuanTransaction> transaction)
{
    const CardApp cardApp = {card->serialNumber(), card->appName()};
    const Transaction t = {cardApp, command, receiver, slot, transaction.release()};
    d->addTransaction(t);
}

void ReaderStatus::updateStatus()
{
    d->ping();
}

void ReaderStatus::updateCard(const std::string &serialNumber, const std::string &appName)
{
    const CardApp cardApp = {serialNumber, appName};
    const Transaction t = {cardApp, updateTransaction.command, nullptr, nullptr, nullptr};
    d->addTransaction(t);
}

void ReaderStatus::learnCards(GpgME::Protocol protocol)
{
    qCDebug(KLEOPATRA_LOG) << __func__ << "- procotol:" << Formatting::displayName(protocol);
    if (protocol == GpgME::CMS && !d->learnCMSTransactionScheduled) {
        d->learnCMSTransactionScheduled = true;
        d->learnCardsCMS();
    } else {
        qCDebug(KLEOPATRA_LOG) << __func__ << "unsupported protocol";
    }
}

std::vector<std::shared_ptr<Card>> ReaderStatus::getCards() const
{
    return d->cardInfos();
}

std::shared_ptr<Card> ReaderStatus::getCard(const std::string &serialNumber, const std::string &appName) const
{
    for (const auto &card : d->cardInfos()) {
        if (card->serialNumber() == serialNumber && card->appName() == appName) {
            qCDebug(KLEOPATRA_LOG) << "ReaderStatus::getCard() - Found card with serial number" << serialNumber << "and app" << appName;
            return card;
        }
    }
    qCWarning(KLEOPATRA_LOG) << "ReaderStatus::getCard() - Did not find card with serial number" << serialNumber << "and app" << appName;
    return std::shared_ptr<Card>();
}

// static
std::string ReaderStatus::switchCard(std::shared_ptr<Context> &ctx, const std::string &serialNumber, Error &err)
{
    return ::switchCard(ctx, serialNumber, err);
}

// static
std::string ReaderStatus::switchApp(std::shared_ptr<Context> &ctx, const std::string &serialNumber, const std::string &appName, Error &err)
{
    return ::switchApp(ctx, serialNumber, appName, err);
}

// static
Error ReaderStatus::switchCardAndApp(const std::string &serialNumber, const std::string &appName)
{
    Error err;
    if (!(engineInfo(GpgEngine).engineVersion() < "2.3.0")) {
        std::unique_ptr<Context> c = Context::createForEngine(AssuanEngine, &err);
        if (err.code() == GPG_ERR_NOT_SUPPORTED) {
            return err;
        }
        auto assuanContext = std::shared_ptr<Context>(c.release());
        const auto resultSerialNumber = switchCard(assuanContext, serialNumber, err);
        if (err || resultSerialNumber != serialNumber) {
            qCWarning(KLEOPATRA_LOG) << "Switching to card" << QString::fromStdString(serialNumber) << "failed";
            if (!err) {
                err = Error::fromCode(GPG_ERR_UNEXPECTED);
            }
            return err;
        }
        const auto resultAppName = switchApp(assuanContext, serialNumber, appName, err);
        if (err || resultAppName != appName) {
            qCWarning(KLEOPATRA_LOG) << "Switching card to" << QString::fromStdString(appName) << "app failed";
            if (!err) {
                err = Error::fromCode(GPG_ERR_UNEXPECTED);
            }
            return err;
        }
    }
    return err;
}

// static
Error ReaderStatus::switchCardBackToOpenPGPApp(const std::string &serialNumber)
{
    Error err;
    if (gpgHasMultiCardMultiAppSupport()) {
        std::unique_ptr<Context> c = Context::createForEngine(AssuanEngine, &err);
        if (err.code() == GPG_ERR_NOT_SUPPORTED) {
            return err;
        }
        auto assuanContext = std::shared_ptr<Context>(c.release());
        ::switchCardBackToOpenPGPApp(assuanContext, serialNumber, err);
    }
    return err;
}

void ReaderStatus::onUpdateCardsStarted()
{
    qCDebug(KLEOPATRA_LOG) << __func__;
    d->currentAction = UpdateCards;
    Q_EMIT updateCardsStarted();
}

void ReaderStatus::onUpdateCardStarted(const std::string &serialNumber, const std::string &appName)
{
    qCDebug(KLEOPATRA_LOG) << __func__ << serialNumber << appName;
    d->currentAction = UpdateCards;
    Q_EMIT updateCardStarted(serialNumber, appName);
}

void ReaderStatus::onUpdateFinished()
{
    qCDebug(KLEOPATRA_LOG) << __func__;
    d->currentAction = NoAction;
    Q_EMIT updateFinished();
}

void ReaderStatus::onStartingLearnCards(GpgME::Protocol protocol)
{
    qCDebug(KLEOPATRA_LOG) << __func__;
    d->currentAction = LearnCards;
    // suspend automatic refreshes of the key cache while smart card keys are learned
    d->keyCacheAutoRefreshSuspension = KeyCache::mutableInstance()->suspendAutoRefresh();
    Q_EMIT startingLearnCards(protocol);
}

void ReaderStatus::onCardsLearned(GpgME::Protocol protocol)
{
    qCDebug(KLEOPATRA_LOG) << __func__;
    d->currentAction = NoAction;
    Q_EMIT cardsLearned(protocol);
    d->learnCMSTransactionScheduled = false;
    d->keyCacheAutoRefreshSuspension.reset();
    // force a reload of the key cache to ensure that all learned certificates are loaded
    KeyCache::mutableInstance()->reload(protocol, KeyCache::ForceReload);
}

std::shared_ptr<Card> ReaderStatus::getCardWithKeyRef(const std::string &serialNumber, const std::string &keyRef) const
{
    for (const auto &card : SmartCard::ReaderStatus::instance()->getCards()) {
        if (card->serialNumber() == serialNumber
            && (card->authenticationKeyRef() == keyRef || card->signingKeyRef() == keyRef || card->encryptionKeyRef() == keyRef)) {
            return card;
        }
    }
    return nullptr;
}

#include "readerstatus.moc"
