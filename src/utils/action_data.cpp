/* -*- mode: c++; c-basic-offset:4 -*-
    utils/action_data.cpp

    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2007 Klarälvdalens Datakonsult AB

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include <config-kleopatra.h>

#include "action_data.h"

#include <KActionCollection>
#include <KToggleAction>
#include <QAction>
#include <QIcon>
#include <QKeySequence>

QAction *Kleo::createAction(const action_data &ad, KActionCollection *coll)
{
    QAction *const a = ad.actionType == KFToggleAction ? new KToggleAction(coll) : new QAction(coll);
    a->setObjectName(QLatin1String(ad.name));
    a->setText(ad.text);
    if (!ad.tooltip.isEmpty()) {
        a->setToolTip(ad.tooltip);
    }
    if (ad.icon) {
        a->setIcon(QIcon::fromTheme(QLatin1String(ad.icon)));
    }
    if (ad.receiver && ad.func) {
        if (ad.actionType == KFToggleAction) {
            QObject::connect(a, &KToggleAction::toggled, ad.receiver, ad.func);
        } else {
            QObject::connect(a, &QAction::triggered, ad.receiver, ad.func);
        }
    }
    a->setEnabled(ad.actionState == Enabled);
    coll->addAction(QLatin1String(ad.name), a);
    return a;
}

QAction *Kleo::make_action_from_data(const action_data &ad, KActionCollection *coll)
{
    QAction *const a = createAction(ad, coll);
    if (!ad.shortcut.isEmpty()) {
        coll->setDefaultShortcut(a, QKeySequence(ad.shortcut));
    }
    return a;
}

void Kleo::make_actions_from_data(const std::vector<action_data> &data, KActionCollection *coll)
{
    for (const auto &actionData : data) {
        coll->addAction(QLatin1String(actionData.name), make_action_from_data(actionData, coll));
    }
}
