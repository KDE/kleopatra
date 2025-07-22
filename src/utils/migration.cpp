// SPDX-FileCopyrightText: 2024 g10 Code GmbH
// SPDX-FileContributor: Tobias Fella <tobias.fella@gnupg.com>
// SPDX-License-Identifier: GPL-2.0-or-later

#include "utils/migration.h"

#include "qt6compat.h"

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

#ifdef Q_OS_WIN
#include <windows.h>
#endif

#ifdef Q_OS_WIN
static void win_outputDebugString_helper(QStringView message)
{
    OutputDebugString(reinterpret_cast<const wchar_t *>(message.utf16()));
}
#endif

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

static void migrateConfigFile(const QString &oldFileName, const QString &newFileName, const QString &oldConfigLocation)
{
    const QFileInfo oldConfigPath{oldConfigLocation + u'/' + oldFileName};
    // all versions of Kleopatra use GNUPGHOME/kleopatra as location for the group config file;
    // Gpg4win 5.x and VSD 3.4 use GNUPGHOME/kleopatra for all config files
    const QDir newConfigDir{Kleo::gnupgHomeDirectory() + "/kleopatra"_L1};
    const QFileInfo newConfigPath{newConfigDir.absoluteFilePath(newFileName)};

    if (!newConfigPath.exists() && oldConfigPath.exists()) {
#ifdef Q_OS_WIN
        if (qApp) {
#endif
            qCInfo(KLEOPATRA_LOG) << "Copying" << oldConfigPath.absoluteFilePath() << "to" << newConfigPath.absoluteFilePath();
#ifdef Q_OS_WIN
        } else {
            win_outputDebugString_helper(u"Copying "_s + oldConfigPath.absoluteFilePath() + u" to "_s + newConfigPath.absoluteFilePath());
        }
#endif
        if (!QDir{}.mkpath(newConfigPath.absolutePath())) {
#ifdef Q_OS_WIN
            if (qApp) {
#endif
                qCWarning(KLEOPATRA_LOG) << "Failed to create folder" << newConfigPath.absolutePath();
#ifdef Q_OS_WIN
            } else {
                win_outputDebugString_helper(u"Failed to create folder "_s + newConfigPath.absolutePath());
            }
#endif
            return;
        }
        const bool ok = QFile::copy(oldConfigPath.absoluteFilePath(), newConfigPath.absoluteFilePath());
        if (!ok) {
#ifdef Q_OS_WIN
            if (qApp) {
#endif
                qCWarning(KLEOPATRA_LOG) << "Unable to copy the old configuration to" << newConfigPath.absoluteFilePath();
#ifdef Q_OS_WIN
            } else {
                win_outputDebugString_helper(u"Unable to copy the old configuration to "_s + newConfigPath.absoluteFilePath());
            }
#endif
        }
    }
}

static void migrateConfigFile(const QString &fileName, const QString &oldConfigLocation)
{
    migrateConfigFile(fileName, fileName, oldConfigLocation);
}

#ifdef Q_OS_WIN
static QString getOldGenericConfigLocation(const QString &applicationName)
{
    // Gpg4win 4.[34] used %APPDATA%/kleopatra as GenericConfigLocation;
    // VSD 3.[123] and GPD 4.3 used %LOCALAPPDATA% as GenericConfigLocation;
    // if application name is not "kleopatra" then we assume VSD/GPD
    return applicationName == "kleopatra"_L1 //
        ? qEnvironmentVariable("APPDATA") + "/kleopatra/"_L1 //
        : qEnvironmentVariable("LOCALAPPDATA") + u'/';
}

void Migration::migrateApplicationConfigFiles(const QString &applicationName)
{
    const QString oldGenericConfigLocation = getOldGenericConfigLocation(applicationName);

    // Migrate the main config file and the state config file to GNUPGHOME/kleopatra/
    migrateConfigFile(u"kleopatrarc"_s, applicationName + "rc"_L1, oldGenericConfigLocation);
    // all Gpg4win-based versions used %APPDATA%/kleopatra as AppDataLocation (for the *staterc file);
    migrateConfigFile(u"kleopatrastaterc"_s, applicationName + "staterc"_L1, qEnvironmentVariable("APPDATA") + "/kleopatra/"_L1);
    // Migrate some more config files
    migrateConfigFile(u"klanguageoverridesrc"_s, oldGenericConfigLocation);
    migrateConfigFile(u"libkleopatrarc"_s, oldGenericConfigLocation);
    migrateConfigFile(u"kxmlgui5/kleopatra/kleopatra.rc"_s, "kxmlgui5/"_L1 + applicationName + "/kleopatra.rc"_L1, oldGenericConfigLocation);
}
#else
static QString getOldGenericConfigLocation(const QString &applicationName)
{
    Q_UNUSED(applicationName)
    return QStandardPaths::writableLocation(QStandardPaths::GenericConfigLocation);
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
    migrateConfigFile(u"kleopatragroupsrc"_s, getOldGenericConfigLocation(qApp->applicationName()));
}
