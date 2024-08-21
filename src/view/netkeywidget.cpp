/*  view/netkeywidget.cpp

    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2017 Intevation GmbH

    SPDX-License-Identifier: GPL-2.0-or-later
*/
#include "netkeywidget.h"

#include "cardkeysview.h"
#include "smartcardactions.h"

#include "kleopatra_debug.h"

#include "smartcard/netkeycard.h"

#include <utils/qt6compat.h>

#include <KLocalizedString>
#include <KMessageWidget>

#include <QIcon>
#include <QVBoxLayout>

using namespace Kleo;
using namespace Kleo::SmartCard;
using namespace Qt::Literals::StringLiterals;

NetKeyWidget::NetKeyWidget(QWidget *parent)
    : SmartCardWidget(AppType::NetKeyApp, parent)
{
    mNullPinWidget = new KMessageWidget{this};
    mContentLayout->addWidget(mNullPinWidget);

    addCardKeysView();
}

NetKeyWidget::~NetKeyWidget() = default;

void NetKeyWidget::setCard(const NetKeyCard *card)
{
    SmartCardWidget::setCard(card);

    /* Only check for the standard NKS NullPIN.
     * According to users of NetKey cards it is fairly uncommon to use SigG certificates at all.
     * So it should be optional to set the SigG pins. */
    if (card->hasNKSNullPin()) {
        mNullPinWidget->setMessageType(KMessageWidget::Information);
        mNullPinWidget->setIcon(QIcon::fromTheme(u"data-information"_s));
        const auto nullTitle = i18nc(
            "NullPIN is a word that is used all over in the netkey "
            "documentation and should be understandable by Netkey cardholders",
            "The NullPIN is still active on this card.");
        const auto nullDescription = i18n("You need to set a PIN before you can use the certificates.");
        mNullPinWidget->setText(QStringLiteral("<b>%1</b><br/>%2").arg(nullTitle, nullDescription));
        mNullPinWidget->setCloseButtonVisible(false);
        if (mNullPinWidget->actions().isEmpty()) {
            mNullPinWidget->addAction(SmartCardActions::createProxyAction(SmartCardActions::instance()->action(u"card_netkey_set_nks_pin"_s), mNullPinWidget));
        }
        mNullPinWidget->setVisible(true);
    } else {
        mNullPinWidget->setVisible(false);
    }
}
