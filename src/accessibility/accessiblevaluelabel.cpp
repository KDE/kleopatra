/*
    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2022 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include <config-kleopatra.h>

#include "accessiblevaluelabel_p.h"

#include "utils/accessibility.h"

#include <QLabel>

using namespace Kleo;

static constexpr QAccessible::Role ValueRole = static_cast<QAccessible::Role>(QAccessible::UserRole);

AccessibleValueLabel::AccessibleValueLabel(QWidget *w)
    : QAccessibleWidget{w, ValueRole}
{
    Q_ASSERT(qobject_cast<QLabel *>(w));
}

QAccessible::State AccessibleValueLabel::state() const
{
    auto state = QAccessibleWidget::state();
    state.readOnly = true;
    return state;
}

QString AccessibleValueLabel::text(QAccessible::Text t) const
{
    QString str;
    switch (t) {
    case QAccessible::Value: {
        str = Kleo::getAccessibleValue(widget());
        if (str.isEmpty()) {
            str = label()->text();
        }
        break;
    }
    default:
        break;
    }
    if (str.isEmpty()) {
        str = QAccessibleWidget::text(t);
    }
    return str;
}

QLabel *AccessibleValueLabel::label() const
{
    return qobject_cast<QLabel *>(object());
}
