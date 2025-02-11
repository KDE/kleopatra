/*
    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2022 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#pragma once

#include <QAccessibleWidget>

class QLabel;

namespace Kleo
{

class AccessibleValueLabel : public QAccessibleWidget
{
public:
    explicit AccessibleValueLabel(QWidget *w);

    QAccessible::State state() const override;
    QString text(QAccessible::Text t) const override;

private:
    QLabel *label() const;
};

}
