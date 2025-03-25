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

static void migrateConfigFile(const QString &fileName)
{
#ifdef Q_OS_WIN
    // On Windows, Gpg4win 4.x used %APPDATA%/kleopatra as GenericConfigLocation;
    // Gpg4win 5.x uses %GNUPGHOME%/kleopatra as GenericConfigLocation
    const QFileInfo oldConfigPath{qEnvironmentVariable("APPDATA") + "/kleopatra/"_L1 + fileName};
#else
    const QFileInfo oldConfigPath{QStandardPaths::writableLocation(QStandardPaths::GenericConfigLocation) + u'/' + fileName};
#endif
    const QDir newConfigDir{Kleo::gnupgHomeDirectory() + "/kleopatra"_L1};
    const QFileInfo newConfigPath{newConfigDir.absoluteFilePath(fileName)};

    if (!newConfigPath.exists() && oldConfigPath.exists()) {
        qCInfo(KLEOPATRA_LOG) << "Copying" << oldConfigPath.absoluteFilePath() << "to" << newConfigPath.absoluteFilePath();
        if (!QDir{}.mkpath(newConfigPath.absolutePath())) {
            qCWarning(KLEOPATRA_LOG) << "Failed to create folder" << newConfigPath.absolutePath();
            return;
        }
        const bool ok = QFile::copy(oldConfigPath.absoluteFilePath(), newConfigPath.absoluteFilePath());
        if (!ok) {
            qCWarning(KLEOPATRA_LOG) << "Unable to copy the old configuration to" << newConfigPath.absoluteFilePath();
        }
    }
}

#ifdef Q_OS_WIN
void Migration::migrateApplicationConfigFiles(const QString &applicationName)
{
    // On Windows, also migrate the main config file and the state config file to GNUPGHOME/kleopatra/
    migrateConfigFile(applicationName + "rc"_L1);
    migrateConfigFile(applicationName + "staterc"_L1);
    // Migrate some more config files
    migrateConfigFile(u"klanguageoverridesrc"_s);
    migrateConfigFile(u"libkleopatrarc"_s);
    migrateConfigFile(u"kxmlgui5/kleopatra/kleopatra.rc"_s);
}
#endif

void Migration::migrate()
{
    auto migrations = KSharedConfig::openStateConfig()->group(QStringLiteral("Migrations"));
    if (!migrations.readEntry("01-key-list-layout", false)) {
        migrateGroupState({}, QStringLiteral("KeyList"));
        migrateGroupState(QStringLiteral("kleopatracertificateselectiondialogrc"), QStringLiteral("CertificateSelectionDialog"));
        migrations.writeEntry("01-key-list-layout", true);
        migrations.sync();
    }

    // Migrate kleopatragroupsrc from old location to GNUPGHOME/kleopatra/
    migrateConfigFile(u"kleopatragroupsrc"_s);
}
