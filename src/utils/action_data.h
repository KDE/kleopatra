/*
    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2007 Klarälvdalens Datakonsult AB

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#pragma once

#include <QString>

#include <functional>
#include <vector>

class QObject;
class QAction;
class KActionCollection;

namespace Kleo
{

enum ActionType {
    RegularQAction,
    KFToggleAction,
};

enum ActionDefaultState {
    Enabled,
    Disabled,
};

struct action_data {
    const char *name;
    QString text;
    QString tooltip;
    const char *icon;
    const QObject *receiver;
    std::function<void(bool)> func;
    QString shortcut;
    ActionType actionType = RegularQAction;
    ActionDefaultState actionState = Enabled;
};

void make_actions_from_data(const std::vector<action_data> &data, KActionCollection *collection);

QAction *make_action_from_data(const action_data &ad, KActionCollection *coll);
QAction *createAction(const action_data &ad, KActionCollection *coll);
}
