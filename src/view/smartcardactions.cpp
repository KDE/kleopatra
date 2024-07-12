/*  view/smartcardactions.cpp

    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2024 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include "smartcardactions.h"

#include <utils/qt6compat.h>

#include <KActionCollection>
#include <KLocalizedString>

#include <algorithm>

using namespace Qt::Literals::StringLiterals;

SmartCardActions::SmartCardActions()
    : mActionCollection{std::make_unique<KActionCollection>(nullptr, u"smartcards"_s)}
{
    mActionCollection->setComponentDisplayName(i18n("Smart Card Management"));

    // window actions
    mActionCollection->addAction(KStandardAction::StandardAction::Close, u"window_close"_s);

    // general actions
    {
        QAction *action = mActionCollection->addAction(KStandardAction::StandardAction::Redisplay, u"reload"_s);
        action->setText(i18nc("@action", "Reload"));
        action->setToolTip(i18nc("@info:tooltip", "Reload smart cards"));
    }
}

SmartCardActions::~SmartCardActions() = default;

std::shared_ptr<const SmartCardActions> SmartCardActions::instance()
{
    return mutableInstance();
}

std::shared_ptr<SmartCardActions> SmartCardActions::mutableInstance()
{
    static std::weak_ptr<SmartCardActions> self;
    if (std::shared_ptr<SmartCardActions> shared = self.lock()) {
        return shared;
    } else {
        const std::shared_ptr<SmartCardActions> s{new SmartCardActions};
        self = s;
        return s;
    }
}

QAction *SmartCardActions::action(const QString &name) const
{
    return mActionCollection->action(name);
}

std::vector<QAction *> SmartCardActions::actions(const std::vector<QString> &names) const
{
    std::vector<QAction *> result;
    result.reserve(names.size());
    std::ranges::transform(names, std::back_inserter(result), [this](const QString &name) {
        return action(name);
    });
    std::erase(result, nullptr);
    return result;
}
