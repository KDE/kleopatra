/*  view/netkeywidget.cpp

    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2017 Intevation GmbH

    SPDX-License-Identifier: GPL-2.0-or-later
*/
#include "netkeywidget.h"

#include "cardkeysview.h"
#include "kleopatraapplication.h"
#include "nullpinwidget.h"
#include "systrayicon.h"

#include "kleopatra_debug.h"

#include "smartcard/netkeycard.h"
#include "smartcard/readerstatus.h"

#include "commands/changepincommand.h"
#include "commands/createcsrforcardkeycommand.h"
#include "commands/createopenpgpkeyfromcardkeyscommand.h"

#include <Libkleo/Algorithm>
#include <Libkleo/Compliance>
#include <Libkleo/Debug>
#include <Libkleo/KeyCache>
#include <Libkleo/KeyHelpers>
#include <Libkleo/KeyListModel>

#include <KLocalizedString>
#include <KMessageBox>
#include <KSeparator>

#include <QHBoxLayout>
#include <QInputDialog>
#include <QLabel>
#include <QPushButton>
#include <QVBoxLayout>

#include <gpgme++/engineinfo.h>

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

    mCardKeysView = new CardKeysView{this, CardKeysView::NoCreated};
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

    if (!(engineInfo(GpgME::GpgSMEngine).engineVersion() < "2.2.26")) { // see https://dev.gnupg.org/T5184
        mCreateCSRButton = new QPushButton(this);
        mCreateCSRButton->setText(i18nc("@action:button", "Create CSR"));
        mCreateCSRButton->setToolTip(i18nc("@info:tooltip", "Create a certificate signing request for a key stored on the card."));
        mCreateCSRButton->setEnabled(false);
        actionLayout->addWidget(mCreateCSRButton);
        connect(mCreateCSRButton, &QPushButton::clicked, this, [this]() {
            createCSR();
        });
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

namespace
{
std::vector<KeyPairInfo> getKeysSuitableForCSRCreation(const NetKeyCard *netKeyCard)
{
    if (netKeyCard->hasNKSNullPin()) {
        return {};
    }

    std::vector<KeyPairInfo> keys;
    Kleo::copy_if(netKeyCard->keyInfos(), std::back_inserter(keys), [](const auto &keyInfo) {
        if (keyInfo.keyRef.substr(0, 9) == "NKS-SIGG.") {
            // SigG certificates for qualified signatures are issued with the physical cards;
            // it's not possible to request a certificate for them
            return false;
        }
        return keyInfo.canSign() //
            && (keyInfo.keyRef.substr(0, 9) == "NKS-NKS3.") //
            && DeVSCompliance::algorithmIsCompliant(keyInfo.algorithm);
    });

    return keys;
}
}

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
    if (mCreateCSRButton) {
        mCreateCSRButton->setEnabled(!getKeysSuitableForCSRCreation(card).empty());
    }

    mCardKeysView->setCard(card);
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

namespace
{
std::string getKeyRef(const std::vector<KeyPairInfo> &keys, QWidget *parent)
{
    QStringList options;
    for (const auto &key : keys) {
        options << QStringLiteral("%1 - %2").arg(QString::fromStdString(key.keyRef), QString::fromStdString(key.grip));
    }

    bool ok;
    const QString choice = QInputDialog::getItem(parent,
                                                 i18n("Select Key"),
                                                 i18n("Please select the key you want to create a certificate signing request for:"),
                                                 options,
                                                 /* current= */ 0,
                                                 /* editable= */ false,
                                                 &ok);
    return ok ? keys[options.indexOf(choice)].keyRef : std::string();
}
}

void NetKeyWidget::createCSR()
{
    const auto netKeyCard = ReaderStatus::instance()->getCard<NetKeyCard>(serialNumber());
    if (!netKeyCard) {
        KMessageBox::error(this, i18n("Failed to find the smartcard with the serial number: %1", QString::fromStdString(serialNumber())));
        return;
    }
    const auto suitableKeys = getKeysSuitableForCSRCreation(netKeyCard.get());
    if (suitableKeys.empty()) {
        KMessageBox::error(this, i18n("Sorry! No keys suitable for creating a certificate signing request found on the smartcard."));
        return;
    }
    const auto keyRef = getKeyRef(suitableKeys, this);
    if (keyRef.empty()) {
        return;
    }
    auto cmd = new CreateCSRForCardKeyCommand(keyRef, serialNumber(), NetKeyCard::AppName, this);
    this->setEnabled(false);
    connect(cmd, &CreateCSRForCardKeyCommand::finished, this, [this]() {
        this->setEnabled(true);
    });
    cmd->start();
}

#include "moc_netkeywidget.cpp"
