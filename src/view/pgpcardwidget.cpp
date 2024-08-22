/*  view/pgpcardwiget.cpp

    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2017 Bundesamt für Sicherheit in der Informationstechnik
    SPDX-FileContributor: Intevation GmbH
    SPDX-FileCopyrightText: 2020, 2022 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include <config-kleopatra.h>

#include "pgpcardwidget.h"

#include "kleopatra_debug.h"

#include "smartcard/openpgpcard.h"

#include <QGridLayout>
#include <QLabel>

#include <KLocalizedString>

using namespace Kleo;
using namespace Kleo::SmartCard;

PGPCardWidget::PGPCardWidget(QWidget *parent)
    : SmartCardWidget(AppType::OpenPGPApp, parent)
{
    {
        mInfoGridLayout->setColumnStretch(mInfoGridLayout->columnCount() - 1, 0); // undo stretch set by base widget
        int row = mInfoGridLayout->rowCount();

        // PIN counters row
        {
            mInfoGridLayout->addWidget(new QLabel(i18nc("@label The number of remaining attempts to enter a PIN or PUK, as in "
                                                        "Remaining attempts: PIN: 2, PUK: 3, Admin PIN: 3",
                                                        "Remaining attempts:")),
                                       row,
                                       0);
            mPinCounterLabel = new QLabel{this};
            mPinCounterLabel->setToolTip(xi18nc("@info:tooltip", "Shows the number of remaining attempts for entering the correct PIN or PUK."));
            mPinCounterLabel->setTextInteractionFlags(Qt::TextBrowserInteraction);
            mInfoGridLayout->addWidget(mPinCounterLabel, row, 1);
        }

        mInfoGridLayout->setColumnStretch(mInfoGridLayout->columnCount(), 1);
    }

    addCardKeysView();
}

void PGPCardWidget::setCard(const OpenPGPCard *card)
{
    SmartCardWidget::setCard(card);

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
    mPinCounterLabel->setText(countersWithLabels.join(QLatin1String(", ")));
}

#include "moc_pgpcardwidget.cpp"
