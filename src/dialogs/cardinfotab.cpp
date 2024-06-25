// SPDX-FileCopyrightText: 2024 g10 Code GmbH
// SPDX-FileContributor: Tobias Fella <tobias.fella@gnupg.com>
// SPDX-License-Identifier: GPL-2.0-or-later

#include "cardinfotab.h"

#include "smartcard/card.h"
#include "smartcard/readerstatus.h"
#include "view/smartcardswidget.h"

#include <Libkleo/Formatting>
#include <Libkleo/KeyCache>
#include <Libkleo/KeyHelpers>
#include <Libkleo/TreeWidget>
#include <Libkleo/UserIDListModel>

#include <KLocalizedString>
#include <KMessageBox>
#include <KSeparator>

#include <QDialogButtonBox>
#include <QHeaderView>
#include <QLabel>
#include <QMenu>
#include <QPushButton>
#include <QVBoxLayout>

#include <QGpgME/Protocol>

#include <gpgme++/key.h>

#include "kleopatra_debug.h"

using namespace Kleo;
using namespace SmartCard;

class CardInfoTab::Private
{
    friend class ::Kleo::CardInfoTab;
    CardInfoTab *const q;

    void loadData();

    enum Columns {
        Keygrip,
        Fingerprint,
        Token,
        Type,
        SerialNumber,
        Owner,
    };

private:
    GpgME::Key key;
    TreeWidget *subkeysTree = nullptr;
    QLabel *placeholderLabel = nullptr;
    QPushButton *reloadButton = nullptr;

public:
    Private(CardInfoTab *qq)
        : q{qq}
    {
        auto vLay = new QVBoxLayout(q);
        vLay->setContentsMargins({});

        subkeysTree = new TreeWidget{q};
        subkeysTree->setAccessibleName(i18n("Subkeys"));
        subkeysTree->setAllColumnsShowFocus(false);
        subkeysTree->setSelectionMode(QAbstractItemView::SingleSelection);
        subkeysTree->setRootIsDecorated(false);

        subkeysTree->setHeaderLabels({
            i18nc("@title:column", "Keygrip"),
            i18nc("@title:column", "Fingerprint"),
            i18nc("@title:column", "Token"),
            i18nc("@title:column", "Type"),
            i18nc("@title:column", "Serial Number"),
            i18nc("@title:column", "Owner"),
        });

        vLay->addWidget(subkeysTree);

        placeholderLabel = new QLabel(i18nc("@info", "Smartcard information is only available for your own certificates."));
        placeholderLabel->setVisible(false);
        placeholderLabel->setAlignment(Qt::AlignHCenter);
        vLay->addWidget(placeholderLabel);

        auto bbox = new QHBoxLayout;

        reloadButton = new QPushButton(i18nc("@action:button", "Reload"));
        bbox->addWidget(reloadButton);

        bbox->addStretch(1);
        vLay->addLayout(bbox);
    }
};

CardInfoTab::CardInfoTab(QWidget *parent)
    : QWidget{parent}
    , d{std::make_unique<Private>(this)}
{
    connect(d->reloadButton, &QPushButton::clicked, this, []() {
        ReaderStatus::mutableInstance()->updateStatus();
    });
    connect(ReaderStatus::instance(), &ReaderStatus::cardAdded, this, [this]() {
        d->loadData();
    });
    connect(ReaderStatus::instance(), &ReaderStatus::cardChanged, this, [this]() {
        d->loadData();
    });
    connect(ReaderStatus::instance(), &ReaderStatus::cardRemoved, this, [this]() {
        d->loadData();
    });
}

CardInfoTab::~CardInfoTab() = default;

GpgME::Key CardInfoTab::key() const
{
    return d->key;
}

void CardInfoTab::Private::loadData()
{
    subkeysTree->clear();
    for (const auto &subkey : key.subkeys()) {
        const auto &cards = KeyCache::instance()->cardsForSubkey(subkey);

        for (const auto &info : cards) {
            auto availableCard = SmartCard::ReaderStatus::instance()->getCardWithKeyRef(info.serialNumber.toStdString(), info.keyRef.toStdString());
            auto item = new QTreeWidgetItem;
            item->setData(Keygrip, Qt::DisplayRole, QString::fromLatin1(subkey.keyGrip()));
            item->setData(Fingerprint, Qt::DisplayRole, Formatting::prettyID(subkey.fingerprint()));
            item->setData(Token, Qt::DisplayRole, info.serialNumber);
            if (availableCard) {
                const QString manufacturer = QString::fromStdString(availableCard->manufacturer());
                const bool manufacturerIsUnknown = manufacturer.isEmpty() || manufacturer == QLatin1String("unknown");
                item->setData(
                    Type,
                    Qt::DisplayRole,
                    manufacturerIsUnknown
                        ? i18nc("Unknown <type> <version> (card)", "Unknown %1 v%2", availableCard->displayAppName(), availableCard->displayAppVersion())
                        : i18nc("<Manufacturer> <type> <version>",
                                "%1 %2 v%3",
                                manufacturer,
                                availableCard->displayAppName(),
                                availableCard->displayAppVersion()));
                item->setData(SerialNumber, Qt::DisplayRole, availableCard->displaySerialNumber());
                item->setData(Owner,
                              Qt::DisplayRole,
                              availableCard->cardHolder().size() > 0 ? availableCard->cardHolder() : i18nc("unknown cardholder", "unknown"));
            } else {
                item->setData(Type, Qt::DisplayRole, i18n("n/a"));
                if (!info.displaySerialNumber.isEmpty()) {
                    item->setData(SerialNumber, Qt::DisplayRole, info.displaySerialNumber);
                } else {
                    item->setData(SerialNumber, Qt::DisplayRole, i18n("n/a"));
                }
                item->setData(Owner, Qt::DisplayRole, i18n("n/a"));
            }
            subkeysTree->addTopLevelItem(item);
        }
    }
    for (int i = 0; i < subkeysTree->columnCount(); i++) {
        subkeysTree->resizeColumnToContents(i);
    }
}

void CardInfoTab::setKey(const GpgME::Key &key)
{
    if (!key.hasSecret()) {
        d->subkeysTree->setVisible(false);
        d->placeholderLabel->setVisible(true);
        d->reloadButton->setEnabled(false);
        return;
    }

    d->key = key;
    d->subkeysTree->header()->resizeSections(QHeaderView::ResizeToContents);
    if (d->subkeysTree->restoreColumnLayout(QStringLiteral("CardInfoTab"))) {
        d->subkeysTree->setColumnHidden(Private::Keygrip, true);
    }
    d->loadData();
    for (int i = 0; i < d->subkeysTree->columnCount(); i++) {
        d->subkeysTree->resizeColumnToContents(i);
    }
}

#include "moc_cardinfotab.cpp"
