// SPDX-FileCopyrightText: 2024 g10 Code GmbH
// SPDX-FileContributor: Tobias Fella <tobias.fella@gnupg.com>
// SPDX-License-Identifier: GPL-2.0-or-later

#include "utils/migration.h"

#include "qt6compat.h"

#include "kleopatra_debug.h"

#include <KConfigGroup>
#include <KSharedConfig>

#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QRegularExpression>
#include <QUuid>

#include <Libkleo/GnuPG>

using namespace Qt::Literals::StringLiterals;

static const QStringList groupStateIgnoredKeys = {
    QStringLiteral("magic"),
};

static void migrateGroupState(const QString &configName, const QString &name)
{
    const auto config = KSharedConfig::openConfig(configName);
    auto groups = config->groupList().filter(QRegularExpression(QStringLiteral("^View #\\d+$")));
    groups.sort();
    QStringList uuids;
    const auto newConfig = KSharedConfig::openStateConfig();
    for (const auto &g : groups) {
        auto group = KConfigGroup(config, g);
        auto newGroup = KConfigGroup(newConfig, QStringLiteral("%1:View %2").arg(name, QUuid::createUuid().toString()));
        for (const auto &key : group.keyList()) {
            if (key == QStringLiteral("column-sizes")) {
                newGroup.writeEntry("ColumnWidths", group.readEntry(key));
            } else if (!groupStateIgnoredKeys.contains(key)) {
                newGroup.writeEntry(key, group.readEntry(key));
            }
        }
        newGroup.sync();
        uuids += newGroup.name();
    }
    if (!uuids.isEmpty()) {
        newConfig->group(name).writeEntry("Tabs", uuids);
    }
}

void Migration::migrate()
{
    auto migrations = KSharedConfig::openStateConfig()->group(QStringLiteral("Migrations"));
    if (!migrations.readEntry("01-key-list-layout", false)) {
        migrateGroupState({}, QStringLiteral("KeyList"));
        migrateGroupState(QStringLiteral("kleopatracertificateselectiondialogrc"), QStringLiteral("CertificateSelectionDialog"));
        migrations.writeEntry("01-key-list-layout", true);
        migrations.sync();
    }

    // Migrate kleopatragroupsrc from ~/.config/ (or %APPDATA%/kleopatra/) to GNUPGHOME/kleopatra/
    const QString groupConfigFilename = u"kleopatragroupsrc"_s;
#ifdef Q_OS_WIN
    const QString oldGroupConfigPath = qEnvironmentVariable("APPDATA") + "/kleopatra/"_L1 + groupConfigFilename;
#else
    const QString oldGroupConfigPath = QStandardPaths::writableLocation(QStandardPaths::GenericConfigLocation) + QLatin1Char('/') + groupConfigFilename;
#endif
    const QDir groupConfigDir{Kleo::gnupgHomeDirectory() + QLatin1String("/kleopatra")};
    const QString groupConfigPath = groupConfigDir.absoluteFilePath(groupConfigFilename);

    if (!QFileInfo::exists(groupConfigPath) && QFileInfo::exists(oldGroupConfigPath)) {
        qCInfo(KLEOPATRA_LOG) << "Copying group configuration from" << oldGroupConfigPath << "to" << groupConfigPath;
        if (!QDir{}.mkpath(groupConfigDir.absolutePath())) {
            qCWarning(KLEOPATRA_LOG) << "Failed to create folder for group configuration:" << groupConfigDir.absolutePath();
            return;
        }
        const bool ok = QFile::copy(oldGroupConfigPath, groupConfigPath);
        if (!ok) {
            qCWarning(KLEOPATRA_LOG) << "Unable to copy the old group configuration to" << groupConfigPath;
        }
    }
}
