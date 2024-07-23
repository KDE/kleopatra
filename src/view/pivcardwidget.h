/*  view/pivcardwiget.h

    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2020 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/
#pragma once

#include "smartcardwidget.h"

class QPushButton;

namespace Kleo
{

namespace SmartCard
{
class PIVCard;
} // namespace SmartCard

class PIVCardWidget : public SmartCardWidget
{
    Q_OBJECT
public:
    explicit PIVCardWidget(QWidget *parent = nullptr);
    ~PIVCardWidget() override;

    void setCard(const SmartCard::PIVCard *card);

private:
    void createKeyFromCardKeys();
    void changePin(const std::string &keyRef);
    void setAdminKey();

private:
    QPushButton *mKeyForCardKeysButton = nullptr;
};
} // namespace Kleo
