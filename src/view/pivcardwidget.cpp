/*  view/pivcardwiget.cpp

    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2020 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include "pivcardwidget.h"

#include "cardkeysview.h"

#include "commands/changepincommand.h"
#include "commands/createopenpgpkeyfromcardkeyscommand.h"
#include "commands/setpivcardapplicationadministrationkeycommand.h"

#include "smartcard/pivcard.h"

#include <Libkleo/Compliance>

#include <KLocalizedString>

#include <QHBoxLayout>
#include <QPushButton>

using namespace GpgME;
using namespace Kleo;
using namespace Kleo::Commands;
using namespace Kleo::SmartCard;

PIVCardWidget::PIVCardWidget(QWidget *parent)
    : SmartCardWidget(parent)
{
    // do not show Created column by default; creation time is not reported by scdaemon for PIV cards
    mCardKeysView = new CardKeysView{this, CardKeysView::NoOptions};
    mContentLayout->addWidget(mCardKeysView, 1);

    auto actionLayout = new QHBoxLayout;

    if (CreateOpenPGPKeyFromCardKeysCommand::isSupported()) {
        mKeyForCardKeysButton = new QPushButton(this);
        mKeyForCardKeysButton->setText(i18nc("@action:button", "Create OpenPGP Key"));
        mKeyForCardKeysButton->setToolTip(i18nc("@info:tooltip", "Create an OpenPGP key for the keys stored on the card."));
        actionLayout->addWidget(mKeyForCardKeysButton);
        connect(mKeyForCardKeysButton, &QPushButton::clicked, this, &PIVCardWidget::createKeyFromCardKeys);
    }

    {
        auto button = new QPushButton(i18nc("@action:button", "Change PIN"), this);
        button->setToolTip(i18nc("@info:tooltip",
                                 "Change the PIV Card Application PIN that activates the PIV Card "
                                 "and enables private key operations using the stored keys."));
        actionLayout->addWidget(button);
        connect(button, &QPushButton::clicked, this, [this]() {
            changePin(PIVCard::pinKeyRef());
        });
    }
    {
        auto button = new QPushButton(i18nc("@action:button", "Change PUK"), this);
        button->setToolTip(i18nc("@info:tooltip", "Change the PIN Unblocking Key that enables a reset of the PIN."));
        actionLayout->addWidget(button);
        connect(button, &QPushButton::clicked, this, [this]() {
            changePin(PIVCard::pukKeyRef());
        });
    }
    {
        auto button = new QPushButton(i18nc("@action:button", "Change Admin Key"), this);
        button->setToolTip(i18nc("@info:tooltip",
                                 "Change the PIV Card Application Administration Key that is used by the "
                                 "PIV Card Application to authenticate the PIV Card Application Administrator and by the "
                                 "administrator (resp. Kleopatra) to authenticate the PIV Card Application."));
        actionLayout->addWidget(button);
        connect(button, &QPushButton::clicked, this, [this]() {
            setAdminKey();
        });
    }

    actionLayout->addStretch(-1);
    mContentLayout->addLayout(actionLayout);
}

PIVCardWidget::~PIVCardWidget()
{
}

void PIVCardWidget::setCard(const PIVCard *card)
{
    SmartCardWidget::setCard(card);

    if (mKeyForCardKeysButton) {
        mKeyForCardKeysButton->setEnabled(card->hasSigningKey() //
                                          && card->hasEncryptionKey() //
                                          && DeVSCompliance::algorithmIsCompliant(card->keyInfo(card->signingKeyRef()).algorithm)
                                          && DeVSCompliance::algorithmIsCompliant(card->keyInfo(card->encryptionKeyRef()).algorithm));
    }
}

void PIVCardWidget::createKeyFromCardKeys()
{
    auto cmd = new CreateOpenPGPKeyFromCardKeysCommand(serialNumber(), PIVCard::AppName, this);
    this->setEnabled(false);
    connect(cmd, &CreateOpenPGPKeyFromCardKeysCommand::finished, this, [this]() {
        this->setEnabled(true);
    });
    cmd->start();
}

void PIVCardWidget::changePin(const std::string &keyRef)
{
    auto cmd = new ChangePinCommand(serialNumber(), PIVCard::AppName, this);
    this->setEnabled(false);
    connect(cmd, &ChangePinCommand::finished, this, [this]() {
        this->setEnabled(true);
    });
    cmd->setKeyRef(keyRef);
    cmd->start();
}

void PIVCardWidget::setAdminKey()
{
    auto cmd = new SetPIVCardApplicationAdministrationKeyCommand(serialNumber(), this);
    this->setEnabled(false);
    connect(cmd, &SetPIVCardApplicationAdministrationKeyCommand::finished, this, [this]() {
        this->setEnabled(true);
    });
    cmd->start();
}

#include "moc_pivcardwidget.cpp"
