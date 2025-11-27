// SPDX-FileCopyrightText: 2024 g10 Code GmbH
// SPDX-FileContributor: Tobias Fella <tobias.fella@gnupg.com>
// SPDX-License-Identifier: GPL-2.0-or-later

#include "utils/migration.h"

#include "kleopatra_debug.h"

#include <KConfigGroup>
#include <KSharedConfig>

#include <QCoreApplication>
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
            if (key == QLatin1StringView("column-sizes")) {
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

static void migrateFile(const QString &oldFileName, const QString &newFileName, const QString &oldLocation, const QString &newLocation)
{
    const QFileInfo oldPath{oldLocation + u'/' + oldFileName};
    const QDir newDir{newLocation};
    const QFileInfo newPath{newDir.absoluteFilePath(newFileName)};

    if (!newPath.exists() && oldPath.exists()) {
        qCInfo(KLEOPATRA_LOG) << "Copying" << oldPath.absoluteFilePath() << "to" << newPath.absoluteFilePath();
        if (!QDir{}.mkpath(newPath.absolutePath())) {
            qCWarning(KLEOPATRA_LOG) << "Failed to create folder" << newPath.absolutePath();
            return;
        }
        const bool ok = QFile::copy(oldPath.absoluteFilePath(), newPath.absoluteFilePath());
        if (!ok) {
            qCWarning(KLEOPATRA_LOG) << "Failed to copy the file to" << newPath.absoluteFilePath();
        }
    }
}

static void migrateFile(const QString &fileName, const QString &oldLocation, const QString &newLocation)
{
    migrateFile(fileName, fileName, oldLocation, newLocation);
}

#ifdef Q_OS_WIN
static QString getOldGenericConfigLocation()
{
    // Gpg4win 4.[34] used %APPDATA%/kleopatra as GenericConfigLocation;
    // VSD 3.[123] and GPD 4.3 used %LOCALAPPDATA% as GenericConfigLocation;
    // if application name is not "kleopatra" then we assume VSD/GPD
    return QCoreApplication::applicationName() == "kleopatra"_L1 //
        ? qEnvironmentVariable("APPDATA") + "/kleopatra/"_L1 //
        : qEnvironmentVariable("LOCALAPPDATA") + u'/';
}

void Migration::migrateApplicationConfigFiles()
{
    const QString applicationName = QCoreApplication::applicationName();
    const QString oldConfigLocation = getOldGenericConfigLocation();
    const QString newConfigLocation = QStandardPaths::writableLocation(QStandardPaths::GenericConfigLocation);
    // all Gpg4win-based versions used %APPDATA%/kleopatra as AppDataLocation (for the *staterc file)
    const QString oldStateLocation = qEnvironmentVariable("APPDATA") + "/kleopatra/"_L1;
    const QString newStateLocation = QStandardPaths::writableLocation(QStandardPaths::GenericStateLocation);

    // Migrate the main config file to QStandardPaths::GenericConfigLocation
    migrateFile(u"kleopatrarc"_s, applicationName + "rc"_L1, oldConfigLocation, newConfigLocation);
    // Migrate the state config file to QStandardPaths::GenericStateLocation;
    migrateFile(u"kleopatrastaterc"_s, applicationName + "staterc"_L1, oldStateLocation, newStateLocation);
    // Migrate some more config files
    migrateFile(u"klanguageoverridesrc"_s, oldConfigLocation, newConfigLocation);
    migrateFile(u"libkleopatrarc"_s, oldConfigLocation, newConfigLocation);
    migrateFile(u"kxmlgui5/kleopatra/kleopatra.rc"_s, "kxmlgui5/"_L1 + applicationName + "/kleopatra.rc"_L1, oldConfigLocation, newConfigLocation);
}
#else
static QString getOldGenericConfigLocation()
{
    return QStandardPaths::writableLocation(QStandardPaths::GenericConfigLocation);
}
#endif

static void removeFilterNames(const QString &fileName)
{
    const QDir configDir{QStandardPaths::writableLocation(QStandardPaths::GenericConfigLocation)};
    const QFileInfo configFilePath{configDir.absoluteFilePath(fileName)};
    if (!configFilePath.exists()) {
        return;
    }
    auto config = KConfig{configFilePath.absoluteFilePath(), KConfig::SimpleConfig};
    const QStringList keyFilterGroups = config.groupList().filter(QRegularExpression(QStringLiteral("^Key Filter #\\d+$")));
    for (const auto &groupName : keyFilterGroups) {
        KConfigGroup group(&config, groupName);
        if (group.hasKey(u"Name"_s)) {
            group.deleteEntry(u"Name"_s);
        }
    }
    if (config.isDirty()) {
        config.sync();
        qCInfo(KLEOPATRA_LOG) << "Removed filter names from" << config.name();
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

    // Migrate kleopatragroupsrc from old location to GNUPGHOME/kleopatra/
    migrateFile(u"kleopatragroupsrc"_s, getOldGenericConfigLocation(), Kleo::gnupgHomeDirectory() + "/kleopatra"_L1);

    removeFilterNames(u"libkleopatrarc"_s);
}
