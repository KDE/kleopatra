/* -*- mode: c++; c-basic-offset:4 -*-
    utils/path-helper.h

    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2009 Klarälvdalens Datakonsult AB

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#pragma once

#include <QtGlobal>

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
 * On Windows, this enables the NTFS permissions check which is an expensive
 * operation. Only use this in the main thread.
 * \sa QFileInfo::isWritable
 */
bool isWritable(const QFileInfo &fi);

#ifdef Q_OS_WIN
void recursivelyRemovePath(const QString &path);
bool recursivelyCopy(const QString &src, const QString &dest);
bool moveDir(const QString &src, const QString &dest);
#endif
}
