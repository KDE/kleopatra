/*  view/netkeywidget.cpp

    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2017 Intevation GmbH

    SPDX-License-Identifier: GPL-2.0-or-later
*/
#include "netkeywidget.h"

#include <smartcard/card.h>

using namespace Kleo;
using namespace Kleo::SmartCard;

NetKeyWidget::NetKeyWidget(QWidget *parent)
    : SmartCardWidget(AppType::NetKeyApp, parent)
{
}

NetKeyWidget::~NetKeyWidget() = default;
