/*  view/p15cardwiget.h

    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2021 g10 Code GmbH
    SPDX-FileContributor: Andre Heinecke <aheinecke@g10code.com>
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/
#pragma once

#include "smartcardwidget.h"

class QLabel;

namespace Kleo
{
class CardKeysView;
class OpenPGPKeyCardWidget;

namespace SmartCard
{
class P15Card;
}

class P15CardWidget : public SmartCardWidget
{
    Q_OBJECT
public:
    explicit P15CardWidget(QWidget *parent = nullptr);
    ~P15CardWidget() override;

    void setCard(const SmartCard::P15Card *card);

private:
    void searchPGPFpr(const std::string &fpr);

private:
    QLabel *mStatusLabel = nullptr;
    QWidget *mOpenPGPKeysSection = nullptr;
    OpenPGPKeyCardWidget *mOpenPGPKeysWidget = nullptr;
    CardKeysView *mCardKeysView = nullptr;
};

}
