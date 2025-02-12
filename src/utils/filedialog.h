/*
    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2009 Klarälvdalens Datakonsult AB

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#pragma once

#include <QString>
#include <QWidget>

namespace Kleo
{
namespace FileDialog
{

QString getOpenFileName(QWidget *parent = nullptr, const QString &caption = QString(), const QString &dirID = QString(), const QString &filter = QString());
QStringList
getOpenFileNames(QWidget *parent = nullptr, const QString &caption = QString(), const QString &dirID = QString(), const QString &filter = QString());
QString getSaveFileName(QWidget *parent = nullptr, const QString &caption = QString(), const QString &dirID = QString(), const QString &filter = QString());
QString getSaveFileNameEx(QWidget *parent = nullptr,
                          const QString &caption = QString(),
                          const QString &dirID = QString(),
                          const QString &proposedFileName = QString(),
                          const QString &filter = QString());

}
}
