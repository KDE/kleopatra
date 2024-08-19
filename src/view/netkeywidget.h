/*  view/netkeywidget.h

    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2017 Intevation GmbH

    SPDX-License-Identifier: GPL-2.0-or-later
*/
#pragma once

#include "smartcardwidget.h"

namespace Kleo
{
class NullPinWidget;

namespace SmartCard
{
class NetKeyCard;
}

class NetKeyWidget : public SmartCardWidget
{
    Q_OBJECT
public:
    explicit NetKeyWidget(QWidget *parent = nullptr);
    ~NetKeyWidget() override;

    void setCard(const SmartCard::NetKeyCard *card);

private:
    NullPinWidget *mNullPinWidget = nullptr;
};
} // namespace Kleo
