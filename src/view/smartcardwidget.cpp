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
#include <utils/qt6compat.h>
#include <view/cardkeysview.h>

#include <Libkleo/Compliance>

#include <KLocalizedString>
#include <KMessageWidget>

#include <QGridLayout>
#include <QLabel>
#include <QMenu>
#include <QScrollArea>
#include <QToolButton>
#include <QVBoxLayout>

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
        auto netKeyCard = static_cast<const NetKeyCard *>(card);
        if (action->objectName() == "card_all_create_openpgp_certificate"_L1) {
            action->setEnabled(!netKeyCard->hasNKSNullPin() && card->hasSigningKey() && card->hasEncryptionKey()
                               && DeVSCompliance::algorithmIsCompliant(card->keyInfo(card->signingKeyRef()).algorithm)
                               && DeVSCompliance::algorithmIsCompliant(card->keyInfo(card->encryptionKeyRef()).algorithm));
        } else if (action->objectName() == "card_netkey_set_nks_pin"_L1) {
            if (!netKeyCard->hasNKSNullPin()) {
                action->setText(i18nc("@action NKS is an identifier for a type of keys on a NetKey card", "Change NKS PIN"));
            }
        } else if (action->objectName() == "card_netkey_set_sigg_pin"_L1) {
            if (!netKeyCard->hasSigGNullPin()) {
                action->setText(i18nc("@action SigG is an identifier for a type of keys on a NetKey card", "Change SigG PIN"));
            }
        }
        break;
    }
    case AppType::OpenPGPApp:
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
    mContentLayout = new QVBoxLayout{areaWidget};
    auto contentLayout = mContentLayout;

    auto upperLayout = new QHBoxLayout;
    {
        // auto gridLayout = new QGridLayout;
        mInfoGridLayout = new QGridLayout;
        auto gridLayout = mInfoGridLayout;
        // gridLayout->setColumnStretch(1, 1);

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

        gridLayout->setColumnStretch(gridLayout->columnCount(), 1);

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
}

void SmartCardWidget::addCardKeysView()
{
    if (mAppType == AppType::NetKeyApp) {
        mNullPinWidget = new KMessageWidget{this};
        mNullPinWidget->setVisible(false);
        mContentLayout->addWidget(mNullPinWidget);
    } else if (mAppType == AppType::P15App) {
        mStatusLabel = new QLabel{this};
        mStatusLabel->setVisible(false);
        mContentLayout->addWidget(mStatusLabel);
    }

    mErrorWidget = new KMessageWidget{this};
    mErrorWidget->setVisible(false);
    mContentLayout->addWidget(mErrorWidget);

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
    mContentLayout->addWidget(mCardKeysView, 1);
}

SmartCardWidget::~SmartCardWidget() = default;

void SmartCardWidget::setCard(const Card *card)
{
    Q_ASSERT(mAppType == card->appType());
    mCard.reset(card->clone());

    mCardTypeField->setValue(cardTypeForDisplay(card));
    mSerialNumberField->setValue(card->displaySerialNumber());
    if (mAppType == AppType::OpenPGPApp) {
        const auto holder = card->cardHolder();
        mCardholderField->setValue(holder.isEmpty() ? i18n("not set") : holder);
        const auto url = card->publicKeyUrl();
        mPublicKeyUrlField->setValue(url.isEmpty() ? i18n("not set") : u"<a href=\"%1\">%1</a>"_s.arg(url.toHtmlEscaped()));
    }

    updateCardActions(mCardActionsButton, card);

    const auto errMsg = card->errorMsg();
    if (!errMsg.isEmpty()) {
        mErrorWidget->setMessageType(KMessageWidget::Error);
        mErrorWidget->setCloseButtonVisible(false);
        mErrorWidget->setText(i18nc("@info", "Error: %1", errMsg));
        mErrorWidget->setVisible(true);
    } else {
        mErrorWidget->setVisible(false);
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

KMessageWidget *SmartCardWidget::nullPinMessageWidget() const
{
    return mNullPinWidget;
}

QLabel *SmartCardWidget::statusLabel() const
{
    return mStatusLabel;
}
