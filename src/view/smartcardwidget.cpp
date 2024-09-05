/*  view/smartcardwidget.cpp

    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2024 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include "smartcardwidget.h"

#include "infofield.h"
#include "smartcardactions.h"

#include <smartcard/card.h>
#include <smartcard/netkeycard.h>
#include <smartcard/pivcard.h>
#include <utils/accessibility.h>
#include <view/cardkeysview.h>

#include <kleopatra_debug.h>
#include <settings.h>

#include <Libkleo/Compliance>
#include <Libkleo/GnuPG>
#include <Libkleo/KeyCache>

#include <KLocalizedString>
#include <KMessageWidget>

#include <QGpgME/ImportFromKeyserverJob>
#include <QGpgME/KeyListJob>
#include <QGpgME/Protocol>

#include <QGridLayout>
#include <QLabel>
#include <QMenu>
#include <QScrollArea>
#include <QToolButton>
#include <QVBoxLayout>

#include <gpgme++/importresult.h>
#include <gpgme++/keylistresult.h>

using namespace Kleo;
using namespace Kleo::SmartCard;
using namespace Qt::Literals::StringLiterals;

static QString cardTypeForDisplay(const Card *card)
{
    switch (card->appType()) {
    case AppType::NetKeyApp:
        return i18nc("1 is a Version number", "NetKey v%1 Card", card->appVersion());
    case AppType::OpenPGPApp: {
        const std::string manufacturer = card->manufacturer();
        const bool manufacturerIsUnknown = manufacturer.empty() || manufacturer == "unknown";
        return (manufacturerIsUnknown //
                    ? i18nc("Placeholder is a version number", "Unknown OpenPGP v%1 card", card->displayAppVersion())
                    : i18nc("First placeholder is manufacturer, second placeholder is a version number",
                            "%1 OpenPGP v%2 card",
                            QString::fromStdString(manufacturer),
                            card->displayAppVersion()));
    }
    case AppType::P15App:
        return i18nc("%1 is a smartcard manufacturer", "%1 PKCS#15 card", QString::fromStdString(card->manufacturer()));
    case AppType::PIVApp:
        return i18nc("%1 version number", "PIV v%1 card", card->displayAppVersion());
    default:
        return {};
    };
}

static std::vector<QAction *> actionsForCard(SmartCard::AppType appType)
{
    std::vector<QString> actions;
    switch (appType) {
    case AppType::NetKeyApp:
        actions = {
            u"card_all_create_openpgp_certificate"_s,
            u"card_netkey_set_nks_pin"_s,
            u"card_netkey_set_sigg_pin"_s,
        };
        break;
    case AppType::OpenPGPApp:
        actions = {
            u"card_pgp_generate_keys_and_certificate"_s,
            u"card_pgp_change_pin"_s,
            u"card_pgp_unblock_card"_s,
            u"card_pgp_change_admin_pin"_s,
            u"card_pgp_change_puk"_s,
            u"card_pgp_change_cardholder"_s,
            u"card_pgp_change_publickeyurl"_s,
        };
        break;
    case AppType::P15App:
        // there are no card actions for generic PKCS#15 cards
        break;
    case AppType::PIVApp:
        actions = {
            u"card_all_create_openpgp_certificate"_s,
            u"card_piv_change_pin"_s,
            u"card_piv_change_puk"_s,
            u"card_piv_change_admin_key"_s,
        };
        break;
    case AppType::NoApp:
        break;
    };
    return SmartCardActions::instance()->actions(actions);
}

static void updateCardAction(QAction *action, const Card *card)
{
    switch (card->appType()) {
    case AppType::NetKeyApp: {
        if (card->pinStates().empty()) {
            action->setEnabled(false);
            return;
        }
        if (action->objectName() == "card_all_create_openpgp_certificate"_L1) {
            action->setEnabled(!card->hasNKSNullPin() && card->hasSigningKey() && card->hasEncryptionKey()
                               && DeVSCompliance::algorithmIsCompliant(card->keyInfo(card->signingKeyRef()).algorithm)
                               && DeVSCompliance::algorithmIsCompliant(card->keyInfo(card->encryptionKeyRef()).algorithm));
        } else if (action->objectName() == "card_netkey_set_nks_pin"_L1) {
            if (!card->hasNKSNullPin()) {
                action->setText(i18nc("@action NKS is an identifier for a type of keys on a NetKey card", "Change NKS PIN"));
            }
        } else if (action->objectName() == "card_netkey_set_sigg_pin"_L1) {
            if (!card->hasSigGNullPin()) {
                action->setText(i18nc("@action SigG is an identifier for a type of keys on a NetKey card", "Change SigG PIN"));
            }
        }
        break;
    }
    case AppType::OpenPGPApp:
        if (action->objectName() == "card_pgp_change_puk"_L1) {
            const auto pinCounters = card->pinCounters();
            const bool pukIsAvailable = (pinCounters.size() == 3) && (pinCounters[1] > 0);
            action->setText(pukIsAvailable ? i18nc("@action", "Change PUK") : i18nc("@action", "Set PUK"));
        }
        break;
    case AppType::P15App:
        break;
    case AppType::PIVApp: {
        if (action->objectName() == "card_all_create_openpgp_certificate"_L1) {
            action->setEnabled(card->hasSigningKey() && card->hasEncryptionKey()
                               && DeVSCompliance::algorithmIsCompliant(card->keyInfo(card->signingKeyRef()).algorithm)
                               && DeVSCompliance::algorithmIsCompliant(card->keyInfo(card->encryptionKeyRef()).algorithm));
        }
        break;
    }
    case AppType::NoApp:
        break;
    };
}

static void updateCardActions(QToolButton *actionsButton, const Card *card)
{
    if (!actionsButton->menu()) {
        const auto actions = actionsForCard(card->appType());
        if (actions.empty()) {
            // there are no card actions for this card app
            return;
        } else {
            actionsButton->setVisible(true);
        }
        auto menu = new QMenu{actionsButton};
        for (auto action : actions) {
            menu->addAction(SmartCardActions::createProxyAction(action, menu));
        }
        actionsButton->setMenu(menu);
    }
    for (auto action : actionsButton->menu()->actions()) {
        updateCardAction(action, card);
    }
}

static void updateNullPinWidget(KMessageWidget *nullPinWidget, const Card *card)
{
    Q_ASSERT(card);
    if (card->appType() != AppType::NetKeyApp) {
        return;
    }
    /* Only check for the standard NKS NullPIN.
     * According to users of NetKey cards it is fairly uncommon to use SigG certificates at all.
     * So it should be optional to set the SigG pins. */
    if (card->hasNKSNullPin()) {
        nullPinWidget->setMessageType(KMessageWidget::Information);
        nullPinWidget->setIcon(QIcon::fromTheme(u"data-information"_s));
        const auto nullTitle = i18nc(
            "NullPIN is a word that is used all over in the netkey "
            "documentation and should be understandable by Netkey cardholders",
            "The NullPIN is still active on this card.");
        const auto nullDescription = i18n("You need to set a PIN before you can use the certificates.");
        nullPinWidget->setText(QStringLiteral("<b>%1</b><br/>%2").arg(nullTitle, nullDescription));
        nullPinWidget->setCloseButtonVisible(false);
        if (nullPinWidget->actions().isEmpty()) {
            nullPinWidget->addAction(SmartCardActions::createProxyAction(SmartCardActions::instance()->action(u"card_netkey_set_nks_pin"_s), nullPinWidget));
        }
        nullPinWidget->setVisible(true);
    } else {
        nullPinWidget->setVisible(false);
    }
}

SmartCardWidget::SmartCardWidget(Kleo::SmartCard::AppType appType, QWidget *parent)
    : QWidget{parent}
    , mAppType{appType}
{
    auto mainLayout = new QVBoxLayout{this};
    mainLayout->setContentsMargins({});

    auto area = new QScrollArea{this};
    area->setFocusPolicy(Qt::NoFocus);
    area->setFrameShape(QFrame::NoFrame);
    area->setWidgetResizable(true);
    mainLayout->addWidget(area);

    auto areaWidget = new QWidget{this};
    area->setWidget(areaWidget);
    auto contentLayout = new QVBoxLayout{areaWidget};

    auto upperLayout = new QHBoxLayout;
    {
        auto gridLayout = new QGridLayout;
        gridLayout->setColumnStretch(1, 1);

        int row = -1;

        row++;
        mCardTypeField = std::make_unique<InfoField>(i18nc("@label", "Card type:"), parent);
        gridLayout->addWidget(mCardTypeField->label(), row, 0);
        gridLayout->addLayout(mCardTypeField->layout(), row, 1);

        row++;
        mSerialNumberField = std::make_unique<InfoField>(i18nc("@label", "Serial number:"), parent);
        gridLayout->addWidget(mSerialNumberField->label(), row, 0);
        gridLayout->addLayout(mSerialNumberField->layout(), row, 1);

        if (mAppType == AppType::OpenPGPApp) {
            row++;
            mCardholderField =
                std::make_unique<InfoField>(i18nc("@label The owner of a smartcard. GnuPG refers to this as cardholder.", "Cardholder:"), parent);
            const auto action = SmartCardActions::createProxyAction(SmartCardActions::instance()->action(u"card_pgp_change_cardholder"_s), parent);
            action->setIcon(QIcon::fromTheme(u"document-edit"_s));
            Kleo::setAccessibleName(action, action->text());
            action->setText({});
            mCardholderField->setAction(action);
            gridLayout->addWidget(mCardholderField->label(), row, 0);
            gridLayout->addLayout(mCardholderField->layout(), row, 1);
        }

        if (mAppType == AppType::OpenPGPApp) {
            row++;
            mPublicKeyUrlField = std::make_unique<InfoField>(i18nc("@label", "Public key URL:"), parent);
            // make the public key URL clickable
            mPublicKeyUrlField->valueLabel()->setTextInteractionFlags(Qt::TextBrowserInteraction);
            mPublicKeyUrlField->valueLabel()->setOpenExternalLinks(true);
            const auto action = SmartCardActions::createProxyAction(SmartCardActions::instance()->action(u"card_pgp_change_publickeyurl"_s), parent);
            action->setIcon(QIcon::fromTheme(u"document-edit"_s));
            Kleo::setAccessibleName(action, action->text());
            action->setText({});
            mPublicKeyUrlField->setAction(action);
            gridLayout->addWidget(mPublicKeyUrlField->label(), row, 0);
            gridLayout->addLayout(mPublicKeyUrlField->layout(), row, 1);
        }

        if (mAppType == AppType::OpenPGPApp) {
            row++;
            mPinCountersField = std::make_unique<InfoField>(i18nc("@label The number of remaining attempts to enter a PIN or PUK, as in "
                                                                  "Remaining attempts: PIN: 2, PUK: 3, Admin PIN: 3",
                                                                  "Remaining attempts:"),
                                                            parent);
            mPinCountersField->setToolTip(xi18nc("@info:tooltip", "Shows the number of remaining attempts for entering the correct PIN or PUK."));
            gridLayout->addWidget(mPinCountersField->label(), row, 0);
            gridLayout->addLayout(mPinCountersField->layout(), row, 1);
        }

        upperLayout->addLayout(gridLayout, 1);
    }
    {
        auto layout = new QVBoxLayout;
        mCardActionsButton = new QToolButton{this};
        mCardActionsButton->setPopupMode(QToolButton::InstantPopup);
        mCardActionsButton->setText(i18nc("@action:button", "Card Actions"));
        mCardActionsButton->setToolTip(i18nc("@info", "Show actions available for this smart card"));
        mCardActionsButton->setVisible(false);
        layout->addWidget(mCardActionsButton);
        layout->addStretch(1);
        upperLayout->addLayout(layout);
    }

    contentLayout->addLayout(upperLayout);

    if (mAppType == AppType::NetKeyApp) {
        mNullPinWidget = new KMessageWidget{this};
        mNullPinWidget->setVisible(false);
        contentLayout->addWidget(mNullPinWidget);
    }

    mErrorWidget = new KMessageWidget{this};
    mErrorWidget->setVisible(false);
    contentLayout->addWidget(mErrorWidget);

    Q_ASSERT(!mCardKeysView);
    switch (mAppType) {
    case AppType::NetKeyApp:
        // do not show Created column by default; creation time is not reported by scdaemon for NetKey cards
        mCardKeysView = new CardKeysView{this, CardKeysView::NoOptions};
        break;
    case AppType::OpenPGPApp:
    case AppType::P15App:
        mCardKeysView = new CardKeysView{this, CardKeysView::ShowCreated};
        break;
    case AppType::PIVApp:
        // do not show Created column by default; creation time is not reported by scdaemon for PIV cards
        mCardKeysView = new CardKeysView{this, CardKeysView::NoOptions};
        break;
    case AppType::NoApp:
        return;
    };
    contentLayout->addWidget(mCardKeysView, 1);
}

SmartCardWidget::~SmartCardWidget()
{
    if (mJob) {
        mJob->slotCancel();
    }
}

void SmartCardWidget::setCard(const Card *card)
{
    Q_ASSERT(mAppType == card->appType());
    const bool firstSetup = !mCard;
    mCard.reset(card->clone());

    mCardTypeField->setValue(cardTypeForDisplay(card));
    mSerialNumberField->setValue(card->displaySerialNumber());
    if (mAppType == AppType::OpenPGPApp) {
        const auto holder = card->cardHolder();
        mCardholderField->setValue(holder.isEmpty() ? ("<em>"_L1 + i18n("not set") + "</em>"_L1) : holder);
        const auto url = card->publicKeyUrl();
        mPublicKeyUrlField->setValue(url.isEmpty() //
                                         ? ("<em>"_L1 + i18n("not set") + "</em>"_L1)
                                         : u"<a href=\"%1\">%1</a>"_s.arg(url.toHtmlEscaped()));

        const auto pinLabels = card->pinLabels();
        const auto pinCounters = card->pinCounters();
        QStringList countersWithLabels;
        countersWithLabels.reserve(pinCounters.size());
        for (const auto &pinCounter : pinCounters) {
            // sanity check
            if (countersWithLabels.size() == pinLabels.size()) {
                break;
            }
            countersWithLabels.push_back(i18nc("label: value", "%1: %2", pinLabels[countersWithLabels.size()], pinCounter));
        }
        mPinCountersField->setValue(countersWithLabels.join(", "_L1));
    }

    updateCardActions(mCardActionsButton, card);

    updateNullPinWidget(mNullPinWidget, card);

    const auto errMsg = card->errorMsg();
    if (!errMsg.isEmpty()) {
        mErrorWidget->setMessageType(KMessageWidget::Error);
        mErrorWidget->setCloseButtonVisible(false);
        mErrorWidget->setText(i18nc("@info", "Error: %1", errMsg));
        mErrorWidget->setVisible(true);
    } else {
        mErrorWidget->setVisible(false);
    }

    if (firstSetup && (mAppType == AppType::OpenPGPApp || mAppType == AppType::P15App)) {
        retrieveOpenPGPCertificate();
    }

    mCardKeysView->setCard(mCard);
}

const Kleo::SmartCard::Card *SmartCardWidget::card() const
{
    return mCard.get();
}

Kleo::SmartCard::AppType SmartCardWidget::cardType() const
{
    return mCard ? mCard->appType() : AppType::NoApp;
}

std::string SmartCardWidget::serialNumber() const
{
    return mCard ? mCard->serialNumber() : std::string{};
}

std::string SmartCardWidget::currentCardSlot() const
{
    if (mCardKeysView) {
        return mCardKeysView->currentCardSlot();
    }
    return {};
}

GpgME::Key SmartCardWidget::currentCertificate() const
{
    if (mCardKeysView) {
        return mCardKeysView->currentCertificate();
    }
    return {};
}

void SmartCardWidget::retrieveOpenPGPCertificate()
{
    Q_ASSERT(mCard);
    Q_ASSERT(mAppType == AppType::OpenPGPApp || mAppType == AppType::P15App);
    Q_ASSERT(!mJob);

    // clear the status message
    Q_EMIT statusMessage({});

    // Auto import the OpenPGP key for the card keys only from LDAP or if explicitly enabled
    if (!(Kleo::keyserver().startsWith("ldap"_L1) || //
          (Settings().alwaysSearchCardOnKeyserver() && Kleo::haveKeyserverConfigured()))) {
        return;
    }
    const auto sigInfo = mCard->keyInfo(mCard->signingKeyRef());
    if (sigInfo.grip.empty()) {
        return;
    }
    const auto key = KeyCache::instance()->findSubkeyByKeyGrip(sigInfo.grip, GpgME::OpenPGP).parent();
    if (!key.isNull()) {
        return;
    }
    qCDebug(KLEOPATRA_LOG) << __func__ << "No key found for key grip" << sigInfo.grip;
    const auto fpr = mCard->keyFingerprint(mCard->signingKeyRef());
    if (fpr.empty()) {
        return;
    }
    qCDebug(KLEOPATRA_LOG) << __func__ << "Should be OpenPGP key" << fpr;
    Q_EMIT statusMessage(i18n("Searching matching certificate in directory service..."));
    qCDebug(KLEOPATRA_LOG) << __func__ << "Looking for" << fpr << "on key server" << Kleo::keyserver();
    auto keyListJob = QGpgME::openpgp()->keyListJob(/* remote = */ true);
    mJob = keyListJob;
    connect(keyListJob, &QGpgME::KeyListJob::result, this, [this](GpgME::KeyListResult, std::vector<GpgME::Key> keys, QString, GpgME::Error) {
        mJob.clear();
        if (keys.size() == 1) {
            qCDebug(KLEOPATRA_LOG) << "retrieveOpenPGPCertificate - Importing" << keys[0].primaryFingerprint();
            auto importJob = QGpgME::openpgp()->importFromKeyserverJob();
            mJob = importJob;
            connect(importJob, &QGpgME::ImportFromKeyserverJob::result, this, [this](GpgME::ImportResult, QString, GpgME::Error) {
                mJob.clear();
                qCDebug(KLEOPATRA_LOG) << "retrieveOpenPGPCertificate - import job done";
                Q_EMIT statusMessage(i18n("The matching certificate was imported successfully."));
            });
            importJob->start(keys);
        } else if (keys.size() > 1) {
            qCDebug(KLEOPATRA_LOG) << "retrieveOpenPGPCertificate - Multiple keys found on server";
            Q_EMIT statusMessage(i18n("Multiple matching certificates were found in directory service."));
        } else {
            qCDebug(KLEOPATRA_LOG) << "retrieveOpenPGPCertificate - No key found on server";
            Q_EMIT statusMessage(i18n("No matching certificate was found in directory service."));
        }
    });
    keyListJob->start({QString::fromStdString(fpr)});
}
