/*  view/pivcardwiget.cpp

    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2020 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include "pivcardwidget.h"

#include "cardkeysview.h"

#include <smartcard/card.h>

#include <QVBoxLayout>

using namespace Kleo;
using namespace Kleo::SmartCard;

PIVCardWidget::PIVCardWidget(QWidget *parent)
    : SmartCardWidget(AppType::PIVApp, parent)
{
    addCardKeysView();
}

PIVCardWidget::~PIVCardWidget() = default;
