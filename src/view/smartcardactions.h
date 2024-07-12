/*  view/smartcardactions.h

    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2024 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#pragma once

#include <QAction>
#include <QString>

#include <memory>
#include <vector>

class KActionCollection;

class SmartCardActions
{
private:
    SmartCardActions();

public:
    ~SmartCardActions();

    static std::shared_ptr<const SmartCardActions> instance();
    static std::shared_ptr<SmartCardActions> mutableInstance();

    /** Returns the action with the name @p name or @c nullptr if no action with this name exists. */
    QAction *action(const QString &name) const;

    /** Returns the actions with the names @p names. Unknown names/actions are skipped,
     * i.e. the list of actions does not contain any @c nullptr. */
    std::vector<QAction *> actions(const std::vector<QString> &names) const;

    template<class Receiver, class Func>
    inline typename std::enable_if<!std::is_convertible<Func, const char *>::value, QMetaObject::Connection>::type
    connectAction(const QString &name, const Receiver *receiver, Func slot) const
    {
        if (QAction *a = action(name)) {
            return QObject::connect(a, &QAction::triggered, receiver, slot);
        }
        return {};
    }

private:
    const std::unique_ptr<KActionCollection> mActionCollection;
};
