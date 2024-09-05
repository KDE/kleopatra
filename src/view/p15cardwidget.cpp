/*  view/p15cardwiget.cpp

    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2021 g10 Code GmbH
    SPDX-FileContributor: Andre Heinecke <aheinecke@g10code.com>
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include "p15cardwidget.h"

#include <smartcard/card.h>

using namespace Kleo;
using namespace Kleo::SmartCard;

P15CardWidget::P15CardWidget(QWidget *parent)
    : SmartCardWidget{AppType::P15App, parent}
{
}

P15CardWidget::~P15CardWidget() = default;

#include "moc_p15cardwidget.cpp"
