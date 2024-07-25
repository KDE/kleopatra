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
#include <smartcard/pivcard.h>
#include <view/cardkeysview.h>

#include <Libkleo/Compliance>

#include <KLocalizedString>

#include <QGridLayout>
#include <QLabel>
#include <QScrollArea>
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

SmartCardWidget::SmartCardWidget(QWidget *parent)
    : QWidget{parent}
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

        gridLayout->setColumnStretch(gridLayout->columnCount(), 1);

        contentLayout->addLayout(gridLayout);
    }
}

SmartCardWidget::~SmartCardWidget() = default;

void SmartCardWidget::setCard(const Card *card)
{
    mCard.reset(card->clone());

    mCardTypeField->setValue(cardTypeForDisplay(card));
    mSerialNumberField->setValue(card->displaySerialNumber());
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

void SmartCardWidget::updateActions()
{
    const auto actions = SmartCardActions::instance();
    if (QAction *action = actions->action(u"card_slot_show_certificate_details"_s)) {
        action->setEnabled(!currentCertificate().isNull());
    }
    switch (cardType()) {
    case AppType::PIVApp: {
        const std::string keyRef = currentCardSlot();
        if (QAction *action = actions->action(u"card_slot_write_key"_s)) {
            action->setEnabled(keyRef == PIVCard::cardAuthenticationKeyRef() || keyRef == PIVCard::keyManagementKeyRef());
        }
        if (QAction *action = actions->action(u"card_slot_write_certificate"_s)) {
            action->setEnabled(currentCertificate().protocol() == GpgME::CMS);
        }
        if (QAction *action = actions->action(u"card_slot_read_certificate"_s)) {
            action->setEnabled(!mCard->certificateData(keyRef).empty());
        }
        if (QAction *action = actions->action(u"card_slot_create_csr"_s)) {
            const auto keyInfo = mCard->keyInfo(keyRef);
            // for PIV trying to create a CSR for the authentication key fails
            action->setEnabled((keyInfo.canSign() || keyInfo.canEncrypt()) //
                               && !keyInfo.grip.empty() //
                               && DeVSCompliance::algorithmIsCompliant(keyInfo.algorithm));
        }
        break;
    }
    case AppType::OpenPGPApp: {
        const std::string keyRef = currentCardSlot();
        if (QAction *action = actions->action(u"card_slot_create_csr"_s)) {
            const auto keyInfo = mCard->keyInfo(keyRef);
            // trying to create a CSR for the encryption key fails (signing the request fails with "Invalid ID")
            action->setEnabled((keyInfo.canCertify() || keyInfo.canSign() || keyInfo.canAuthenticate()) //
                               && !keyInfo.grip.empty() //
                               && DeVSCompliance::algorithmIsCompliant(keyInfo.algorithm));
        }
        break;
    }
    case AppType::NetKeyApp:
    case AppType::P15App:
        // nothing to do
        break;
    case AppType::NoApp:
        // cannot happen
        break;
    };
}
