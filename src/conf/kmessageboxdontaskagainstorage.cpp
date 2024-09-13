// This file is part of the KDE libraries
// SPDX-FileCopyrightText: 2012 David Faure <faure+bluesystems@kde.org>
// SPDX-License-Identifier: LGPL-2.0-only OR LGPL-3.0-only OR LicenseRef-KDE-Accepted-LGPL

#include "kmessageboxdontaskagainstorage.h"

#include <KConfigGroup>
#include <KSharedConfig>

bool KMessageBoxDontAskAgainConfigStorage::shouldBeShownTwoActions(const QString &dontShowAgainName, KMessageBox::ButtonCode &result)
{
    KConfigGroup cg(KMessageBox_againConfig ? KMessageBox_againConfig : KSharedConfig::openConfig().data(), QStringLiteral("Notification Messages"));
    const QString dontAsk = cg.readEntry(dontShowAgainName, QString()).toLower();
    if (dontAsk == QLatin1StringView("yes") || dontAsk == QLatin1StringView("true")) {
        result = KMessageBox::PrimaryAction;
        return false;
    }
    if (dontAsk == QLatin1StringView("no") || dontAsk == QLatin1StringView("false")) {
        result = KMessageBox::SecondaryAction;
        return false;
    }
    return true;
}

bool KMessageBoxDontAskAgainConfigStorage::shouldBeShownContinue(const QString &dontShowAgainName)
{
    KConfigGroup cg(KMessageBox_againConfig ? KMessageBox_againConfig : KSharedConfig::openConfig().data(), QStringLiteral("Notification Messages"));
    return cg.readEntry(dontShowAgainName, true);
}

void KMessageBoxDontAskAgainConfigStorage::saveDontShowAgainTwoActions(const QString &dontShowAgainName, KMessageBox::ButtonCode result)
{
    KConfigGroup::WriteConfigFlags flags = KConfig::Persistent;
    if (dontShowAgainName[0] == QLatin1Char(':')) {
        flags |= KConfigGroup::Global;
    }
    KConfigGroup cg(KMessageBox_againConfig ? KMessageBox_againConfig : KSharedConfig::openConfig().data(), QStringLiteral("Notification Messages"));
    cg.writeEntry(dontShowAgainName, result == KMessageBox::PrimaryAction, flags);
    cg.sync();
}

void KMessageBoxDontAskAgainConfigStorage::saveDontShowAgainContinue(const QString &dontShowAgainName)
{
    KConfigGroup::WriteConfigFlags flags = KConfigGroup::Persistent;
    if (dontShowAgainName[0] == QLatin1Char(':')) {
        flags |= KConfigGroup::Global;
    }
    KConfigGroup cg(KMessageBox_againConfig ? KMessageBox_againConfig : KSharedConfig::openConfig().data(), QStringLiteral("Notification Messages"));
    cg.writeEntry(dontShowAgainName, false, flags);
    cg.sync();
}

void KMessageBoxDontAskAgainConfigStorage::enableAllMessages()
{
    KConfig *config = KMessageBox_againConfig ? KMessageBox_againConfig : KSharedConfig::openConfig().data();
    if (!config->hasGroup(QStringLiteral("Notification Messages"))) {
        return;
    }

    KConfigGroup cg(config, QStringLiteral("Notification Messages"));

    typedef QMap<QString, QString> configMap;

    const configMap map = cg.entryMap();

    configMap::ConstIterator it;
    for (it = map.begin(); it != map.end(); ++it) {
        cg.deleteEntry(it.key());
    }
}

void KMessageBoxDontAskAgainConfigStorage::enableMessage(const QString &dontShowAgainName)
{
    KConfig *config = KMessageBox_againConfig ? KMessageBox_againConfig : KSharedConfig::openConfig().data();
    if (!config->hasGroup(QStringLiteral("Notification Messages"))) {
        return;
    }

    KConfigGroup cg(config, QStringLiteral("Notification Messages"));

    cg.deleteEntry(dontShowAgainName);
    config->sync();
}
