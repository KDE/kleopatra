/*  view/smartcardwidget.cpp

    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2017 Bundesamt für Sicherheit in der Informationstechnik
    SPDX-FileContributor: Intevation GmbH
    SPDX-FileCopyrightText: 2020 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include "smartcardwidget.h"

#include "smartcard/netkeycard.h"
#include "smartcard/openpgpcard.h"
#include "smartcard/p15card.h"
#include "smartcard/pivcard.h"
#include "smartcard/readerstatus.h"
#include "smartcard/utils.h"

#include "view/netkeywidget.h"
#include "view/p15cardwidget.h"
#include "view/pgpcardwidget.h"
#include "view/pivcardwidget.h"

#include "kleopatra_debug.h"

#include <KLocalizedString>

#include <QHBoxLayout>
#include <QLabel>
#include <QPointer>
#include <QPushButton>
#include <QStackedWidget>
#include <QTabWidget>
#include <QVBoxLayout>

using namespace Kleo;
using namespace Kleo::SmartCard;

namespace
{
class PlaceHolderWidget : public QWidget
{
    Q_OBJECT
public:
    explicit PlaceHolderWidget(QWidget *parent = nullptr)
        : QWidget{parent}
    {
        auto lay = new QVBoxLayout;
        lay->addStretch(-1);

        const QStringList supported = QStringList() << i18nc("OpenPGP refers to a smartcard protocol", "OpenPGP v2.0 - v3.3")
                                                    << i18nc("Gnuk is a cryptographic token for GnuPG", "Gnuk")
                                                    << i18nc("NetKey refers to a smartcard protocol", "NetKey v3")
                                                    << i18nc("PIV refers to a smartcard protocol", "PIV (requires GnuPG 2.3 or later)")
                                                    << i18nc("CardOS is a smartcard operating system", "CardOS 5 (various apps)");
        lay->addWidget(new QLabel(QStringLiteral("\t\t<h3>") + i18n("Please insert a compatible smartcard.") + QStringLiteral("</h3>"), this));
        lay->addSpacing(10);
        lay->addWidget(new QLabel(QStringLiteral("\t\t") + i18n("Kleopatra currently supports the following card types:") + QStringLiteral("<ul><li>")
                                      + supported.join(QLatin1String("</li><li>")) + QStringLiteral("</li></ul>"),
                                  this));
        lay->addSpacing(10);
        {
            auto hbox = new QHBoxLayout;
            hbox->addStretch(1);
            mReloadButton = new QPushButton{i18n("Reload"), this};
            hbox->addWidget(mReloadButton);
            hbox->addStretch(1);
            lay->addLayout(hbox);
        }
        lay->addStretch(-1);

        auto hLay = new QHBoxLayout(this);
        hLay->addStretch(-1);
        hLay->addLayout(lay);
        hLay->addStretch(-1);
        lay->addStretch(-1);

        connect(mReloadButton, &QPushButton::clicked, this, &PlaceHolderWidget::reload);
    }

Q_SIGNALS:
    void reload();

private:
    QPushButton *mReloadButton = nullptr;
};
} // namespace

class SmartCardWidget::Private
{
    friend class ::Kleo::SmartCardWidget;

public:
    Private(SmartCardWidget *qq);

    void cardAddedOrChanged(const std::string &serialNumber, const std::string &appName);
    void cardRemoved(const std::string &serialNumber, const std::string &appName);

private:
    template<typename C, typename W>
    void cardAddedOrChanged(const std::string &serialNumber);

private:
    SmartCardWidget *const q;
    QMap<std::pair<std::string, std::string>, QPointer<QWidget>> mCardWidgets;
    PlaceHolderWidget *mPlaceHolderWidget;
    QStackedWidget *mStack;
    QTabWidget *mTabWidget;
};

SmartCardWidget::Private::Private(SmartCardWidget *qq)
    : q{qq}
{
    auto vLay = new QVBoxLayout(q);

    mStack = new QStackedWidget;
    vLay->addWidget(mStack);

    mPlaceHolderWidget = new PlaceHolderWidget;
    mStack->addWidget(mPlaceHolderWidget);

    mTabWidget = new QTabWidget;
    mStack->addWidget(mTabWidget);

    mStack->setCurrentWidget(mPlaceHolderWidget);

    connect(mPlaceHolderWidget, &PlaceHolderWidget::reload, q, &SmartCardWidget::reload);
    connect(ReaderStatus::instance(), &ReaderStatus::cardAdded, q, [this](const std::string &serialNumber, const std::string &appName) {
        cardAddedOrChanged(serialNumber, appName);
    });
    connect(ReaderStatus::instance(), &ReaderStatus::cardChanged, q, [this](const std::string &serialNumber, const std::string &appName) {
        cardAddedOrChanged(serialNumber, appName);
    });
    connect(ReaderStatus::instance(), &ReaderStatus::cardRemoved, q, [this](const std::string &serialNumber, const std::string &appName) {
        cardRemoved(serialNumber, appName);
    });
}

void SmartCardWidget::Private::cardAddedOrChanged(const std::string &serialNumber, const std::string &appName)
{
    if (appName == SmartCard::NetKeyCard::AppName) {
        cardAddedOrChanged<NetKeyCard, NetKeyWidget>(serialNumber);
    } else if (appName == SmartCard::OpenPGPCard::AppName) {
        cardAddedOrChanged<OpenPGPCard, PGPCardWidget>(serialNumber);
    } else if (appName == SmartCard::PIVCard::AppName) {
        cardAddedOrChanged<PIVCard, PIVCardWidget>(serialNumber);
    } else if (appName == SmartCard::P15Card::AppName) {
        cardAddedOrChanged<P15Card, P15CardWidget>(serialNumber);
    } else {
        qCWarning(KLEOPATRA_LOG) << "SmartCardWidget::Private::cardAddedOrChanged:"
                                 << "App" << appName.c_str() << "is not supported";
    }
}

namespace
{
static QString getCardLabel(const std::shared_ptr<Card> &card)
{
    if (!card->cardHolder().isEmpty()) {
        return i18nc("@title:tab smartcard application - name of card holder - serial number of smartcard",
                     "%1 - %2 - %3",
                     displayAppName(card->appName()),
                     card->cardHolder(),
                     card->displaySerialNumber());
    } else {
        return i18nc("@title:tab smartcard application - serial number of smartcard", "%1 - %2", displayAppName(card->appName()), card->displaySerialNumber());
    }
}
}

template<typename C, typename W>
void SmartCardWidget::Private::cardAddedOrChanged(const std::string &serialNumber)
{
    const auto card = ReaderStatus::instance()->getCard<C>(serialNumber);
    if (!card) {
        qCWarning(KLEOPATRA_LOG) << "SmartCardWidget::Private::cardAddedOrChanged:"
                                 << "New or changed card" << serialNumber.c_str() << "with app" << C::AppName.c_str() << "not found";
        return;
    }
    W *cardWidget = dynamic_cast<W *>(mCardWidgets.value({serialNumber, C::AppName}).data());
    if (!cardWidget) {
        cardWidget = new W;
        mCardWidgets.insert({serialNumber, C::AppName}, cardWidget);
        mTabWidget->addTab(cardWidget, getCardLabel(card));
        if (mCardWidgets.size() == 1) {
            mStack->setCurrentWidget(mTabWidget);
        }
    }
    cardWidget->setCard(card.get());
}

void SmartCardWidget::Private::cardRemoved(const std::string &serialNumber, const std::string &appName)
{
    QWidget *cardWidget = mCardWidgets.take({serialNumber, appName});
    if (cardWidget) {
        const int index = mTabWidget->indexOf(cardWidget);
        if (index != -1) {
            mTabWidget->removeTab(index);
        }
        delete cardWidget;
    }
    if (mCardWidgets.empty()) {
        mStack->setCurrentWidget(mPlaceHolderWidget);
    }
}

SmartCardWidget::SmartCardWidget(QWidget *parent)
    : QWidget{parent}
    , d{std::make_unique<Private>(this)}
{
}

SmartCardWidget::~SmartCardWidget() = default;

void SmartCardWidget::showCards(const std::vector<std::shared_ptr<Kleo::SmartCard::Card>> &cards)
{
    for (const auto &card : cards) {
        d->cardAddedOrChanged(card->serialNumber(), card->appName());
    }
}

void SmartCardWidget::reload()
{
    ReaderStatus::mutableInstance()->updateStatus();
}

#include "smartcardwidget.moc"
