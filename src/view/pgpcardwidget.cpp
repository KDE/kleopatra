/*  view/pgpcardwiget.cpp

    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2017 Bundesamt für Sicherheit in der Informationstechnik
    SPDX-FileContributor: Intevation GmbH
    SPDX-FileCopyrightText: 2020, 2022 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include "pgpcardwidget.h"

#include "smartcard/openpgpcard.h"

using namespace Kleo;
using namespace Kleo::SmartCard;

PGPCardWidget::PGPCardWidget(QWidget *parent)
    : SmartCardWidget(AppType::OpenPGPApp, parent)
{
    addCardKeysView();
}

void PGPCardWidget::setCard(const OpenPGPCard *card)
{
    SmartCardWidget::setCard(card);
}
