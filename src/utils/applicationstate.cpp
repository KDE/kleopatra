/*
    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2022 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include <config-kleopatra.h>

#include "applicationstate.h"

#include <KConfigGroup>
#include <KSharedConfig>

#include <QFileInfo>
#include <QStandardPaths>

QString ApplicationState::lastUsedExportDirectory()
{
    QString ret;
    const KConfigGroup stateConfig{KSharedConfig::openStateConfig(), QLatin1StringView("Export")};
    ret = stateConfig.readEntry("LastDirectory");
    if (ret.isEmpty()) {
        // try the normal config for backward compatibility
        const KConfigGroup config{KSharedConfig::openConfig(), QLatin1StringView("ExportDialog")};
        ret = config.readEntry("LastDirectory");
    }
    return ret.isEmpty() ? QStandardPaths::writableLocation(QStandardPaths::DocumentsLocation) : ret;
}

void ApplicationState::setLastUsedExportDirectory(const QString &path)
{
    if (path.isEmpty()) {
        return;
    }
    const QFileInfo fi{path};
    KConfigGroup stateConfig{KSharedConfig::openStateConfig(), QLatin1StringView("Export")};
    stateConfig.writeEntry("LastDirectory", fi.isDir() ? fi.absoluteFilePath() : fi.absolutePath());
}
