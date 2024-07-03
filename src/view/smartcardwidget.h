/*  view/smartcardwidget.h

    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2024 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/
#pragma once

#include <QWidget>

#include <string>

class SmartCardWidget : public QWidget
{
public:
    SmartCardWidget(QWidget *parent = nullptr);
    ~SmartCardWidget() override;

protected:
    std::string mSerialNumber;
};
