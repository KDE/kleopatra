/* -*- mode: c++; c-basic-offset:4 -*-
    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2009 Klarälvdalens Datakonsult AB

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#pragma once

#include <QtSystemDetection>

class QString;
#include <QStringList>
class QDir;
class QFileInfo;

namespace Kleo
{

QString heuristicBaseDirectory(const QStringList &files);
QStringList makeRelativeTo(const QDir &dir, const QStringList &files);
QStringList makeRelativeTo(const QString &dir, const QStringList &files);
QString stripSuffix(const QString &fileName);

/**
 * Checks if the file/directory referenced by \p fi is writable.
 *
 * On Windows, a temporary file is created to check if a directory is writable.
 * \sa QFileInfo::isWritable
 */
bool isWritable(const QFileInfo &fi);

#ifdef Q_OS_WIN
void recursivelyRemovePath(const QString &path);
bool recursivelyCopy(const QString &src, const QString &dest);
bool moveDir(const QString &src, const QString &dest);
#endif
}
