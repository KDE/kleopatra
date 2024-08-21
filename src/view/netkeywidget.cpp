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

#include <KLocalizedString>

#include <QLabel>
#include <QVBoxLayout>

using namespace Kleo;
using namespace Kleo::SmartCard;

NetKeyWidget::NetKeyWidget(QWidget *parent)
    : SmartCardWidget(AppType::NetKeyApp, parent)
{
    mNullPinWidget = new NullPinWidget{this};
    mContentLayout->addWidget(mNullPinWidget);

    mErrorLabel = new QLabel{this};
    mErrorLabel->setVisible(false);
    mContentLayout->addWidget(mErrorLabel);

    addCardKeysView();
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

    const auto errMsg = card->errorMsg();
    if (!errMsg.isEmpty()) {
        mErrorLabel->setText(QStringLiteral("<b>%1:</b> %2").arg(i18n("Error"), errMsg));
        mErrorLabel->setVisible(true);
    } else {
        mErrorLabel->setVisible(false);
    }
}
