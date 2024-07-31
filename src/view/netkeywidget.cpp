/*  view/netkeywidget.cpp

    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2017 Intevation GmbH

    SPDX-License-Identifier: GPL-2.0-or-later
*/
#include "netkeywidget.h"

#include "cardkeysview.h"
#include "nullpinwidget.h"

#include "kleopatra_debug.h"

#include "smartcard/netkeycard.h"
#include "smartcard/readerstatus.h"

#include "commands/changepincommand.h"
#include "commands/createopenpgpkeyfromcardkeyscommand.h"

#include <Libkleo/Compliance>

#include <KLocalizedString>
#include <KMessageBox>

#include <QHBoxLayout>
#include <QLabel>
#include <QPushButton>

using namespace Kleo;
using namespace Kleo::SmartCard;
using namespace Kleo::Commands;

NetKeyWidget::NetKeyWidget(QWidget *parent)
    : SmartCardWidget(parent)
{
    mNullPinWidget = new NullPinWidget{this};
    mContentLayout->addWidget(mNullPinWidget);

    mErrorLabel = new QLabel{this};
    mErrorLabel->setVisible(false);
    mContentLayout->addWidget(mErrorLabel);

    // do not show Created column by default; creation time is not reported by scdaemon for NetKey cards
    mCardKeysView = new CardKeysView{this, CardKeysView::NoOptions};
    mContentLayout->addWidget(mCardKeysView, 1);

    // The action area
    auto actionLayout = new QHBoxLayout();

    if (CreateOpenPGPKeyFromCardKeysCommand::isSupported()) {
        mKeyForCardKeysButton = new QPushButton(this);
        mKeyForCardKeysButton->setText(i18nc("@action:button", "Create OpenPGP Key"));
        mKeyForCardKeysButton->setToolTip(i18nc("@info:tooltip", "Create an OpenPGP key for the keys stored on the card."));
        actionLayout->addWidget(mKeyForCardKeysButton);
        connect(mKeyForCardKeysButton, &QPushButton::clicked, this, &NetKeyWidget::createKeyFromCardKeys);
    }

    mChangeNKSPINBtn = new QPushButton{this};
    mChangeNKSPINBtn->setText(i18nc("@action:button NKS is an identifier for a type of keys on a NetKey card", "Change NKS PIN"));
    mChangeSigGPINBtn = new QPushButton{this};
    mChangeSigGPINBtn->setText(i18nc("@action:button SigG is an identifier for a type of keys on a NetKey card", "Change SigG PIN"));

    connect(mChangeNKSPINBtn, &QPushButton::clicked, this, [this]() {
        doChangePin(NetKeyCard::nksPinKeyRef());
    });
    connect(mChangeSigGPINBtn, &QPushButton::clicked, this, [this]() {
        doChangePin(NetKeyCard::sigGPinKeyRef());
    });

    actionLayout->addWidget(mChangeNKSPINBtn);
    actionLayout->addWidget(mChangeSigGPINBtn);
    actionLayout->addStretch(1);

    mContentLayout->addLayout(actionLayout);
}

NetKeyWidget::~NetKeyWidget() = default;

void NetKeyWidget::setCard(const NetKeyCard *card)
{
    SmartCardWidget::setCard(card);

    mNullPinWidget->setSerialNumber(serialNumber());
    /* According to users of NetKey Cards it is fairly uncommon
     * to use SigG Certificates at all. So it should be optional to set the pins. */
    mNullPinWidget->setVisible(card->hasNKSNullPin() /*|| card->hasSigGNullPin()*/);

    mNullPinWidget->setSigGVisible(false /*card->hasSigGNullPin()*/);
    mNullPinWidget->setNKSVisible(card->hasNKSNullPin());
    mChangeNKSPINBtn->setEnabled(!card->hasNKSNullPin());

    if (card->hasSigGNullPin()) {
        mChangeSigGPINBtn->setText(i18nc("SigG is an identifier for a type of keys on a NetKey card", "Set SigG PIN"));
    } else {
        mChangeSigGPINBtn->setText(i18nc("SigG is an identifier for a type of keys on a NetKey card", "Change SigG PIN"));
    }

    const auto errMsg = card->errorMsg();
    if (!errMsg.isEmpty()) {
        mErrorLabel->setText(QStringLiteral("<b>%1:</b> %2").arg(i18n("Error"), errMsg));
        mErrorLabel->setVisible(true);
    } else {
        mErrorLabel->setVisible(false);
    }

    if (mKeyForCardKeysButton) {
        mKeyForCardKeysButton->setEnabled(!card->hasNKSNullPin() && card->hasSigningKey() && card->hasEncryptionKey()
                                          && DeVSCompliance::algorithmIsCompliant(card->keyInfo(card->signingKeyRef()).algorithm)
                                          && DeVSCompliance::algorithmIsCompliant(card->keyInfo(card->encryptionKeyRef()).algorithm));
    }
}

void NetKeyWidget::doChangePin(const std::string &keyRef)
{
    const auto netKeyCard = ReaderStatus::instance()->getCard<NetKeyCard>(serialNumber());
    if (!netKeyCard) {
        KMessageBox::error(this, i18n("Failed to find the smartcard with the serial number: %1", QString::fromStdString(serialNumber())));
        return;
    }

    auto cmd = new ChangePinCommand(serialNumber(), NetKeyCard::AppName, this);
    this->setEnabled(false);
    connect(cmd, &ChangePinCommand::finished, this, [this]() {
        this->setEnabled(true);
    });
    cmd->setKeyRef(keyRef);
    if ((keyRef == NetKeyCard::nksPinKeyRef() && netKeyCard->hasNKSNullPin()) //
        || (keyRef == NetKeyCard::sigGPinKeyRef() && netKeyCard->hasSigGNullPin())) {
        cmd->setMode(ChangePinCommand::NullPinMode);
    }
    cmd->start();
}

void NetKeyWidget::createKeyFromCardKeys()
{
    auto cmd = new CreateOpenPGPKeyFromCardKeysCommand(serialNumber(), NetKeyCard::AppName, this);
    this->setEnabled(false);
    connect(cmd, &CreateOpenPGPKeyFromCardKeysCommand::finished, this, [this]() {
        this->setEnabled(true);
    });
    cmd->start();
}

#include "moc_netkeywidget.cpp"
