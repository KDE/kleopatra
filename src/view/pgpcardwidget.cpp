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

#include <utils/qt-cxx20-compat.h>

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

        mInfoGridLayout->setColumnStretch(mInfoGridLayout->columnCount(), 1);
    }

    addCardKeysView();
}

void PGPCardWidget::setCard(const OpenPGPCard *card)
{
    SmartCardWidget::setCard(card);
}
