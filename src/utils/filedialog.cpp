/*
    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2009 Klarälvdalens Datakonsult AB
    SPDX-FileCopyrightText: 2025 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include <config-kleopatra.h>

#include "filedialog.h"

#include <KConfigGroup>
#include <KSharedConfig>

#include <QDir>
#include <QFileDialog>

using namespace Kleo;
using namespace Qt::Literals;

static QString dir(const QString &id)
{
    const KConfigGroup config{KSharedConfig::openStateConfig(), u"File System Locations"_s};
    const QString path = config.readPathEntry(id, QStandardPaths::writableLocation(QStandardPaths::DocumentsLocation));
    return QFile::exists(path) ? path : QStandardPaths::writableLocation(QStandardPaths::DocumentsLocation);
}

static void update(const QString &fname, const QString &id)
{
    if (!fname.isEmpty()) {
        KConfigGroup config{KSharedConfig::openStateConfig(), u"File System Locations"_s};
        config.writePathEntry(id, QFileInfo(fname).absolutePath());
        config.sync();
    }
}

QString FileDialog::getOpenFileName(QWidget *parent, const QString &caption, const QString &dirID, const QString &filter)
{
    const QString fname = QFileDialog::getOpenFileName(parent, caption, dir(dirID), filter);
    update(fname, dirID);
    return fname;
}

QStringList FileDialog::getOpenFileNames(QWidget *parent, const QString &caption, const QString &dirID, const QString &filter)
{
    const QStringList files = QFileDialog::getOpenFileNames(parent, caption, dir(dirID), filter);
    if (!files.empty()) {
        update(files.front(), dirID);
    }
    return files;
}

QString FileDialog::getSaveFileName(QWidget *parent, const QString &caption, const QString &dirID, const QString &filter)
{
    const QString fname = QFileDialog::getSaveFileName(parent, caption, dir(dirID), filter);
    update(fname, dirID);
    return fname;
}

QString FileDialog::getSaveFileNameEx(QWidget *parent, const QString &caption, const QString &dirID, const QString &proposedFileName, const QString &filter)
{
    if (proposedFileName.isEmpty()) {
        return getSaveFileName(parent, caption, dirID, filter);
    }
    const QString fname = QFileDialog::getSaveFileName(parent, caption, QDir(dir(dirID)).filePath(proposedFileName), filter);
    update(fname, dirID);
    return fname;
}
