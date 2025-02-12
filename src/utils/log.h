/*
    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2008 Klarälvdalens Datakonsult AB

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#pragma once

#include <QtLogging>

#include <memory>

#include <cstdio>

class QIODevice;
class QString;

namespace Kleo
{

class Log
{
public:
    enum OpenMode {
        Read = 0x1,
        Write = 0x2,
    };

    static void messageHandler(QtMsgType type, const QMessageLogContext &ctx, const QString &msg);

    static std::shared_ptr<const Log> instance();
    static std::shared_ptr<Log> mutableInstance();

    ~Log();

    bool ioLoggingEnabled() const;
    void setIOLoggingEnabled(bool enabled);

    QString outputDirectory() const;
    void setOutputDirectory(const QString &path);

    std::shared_ptr<QIODevice> createIOLogger(const std::shared_ptr<QIODevice> &wrapped, const QString &prefix, OpenMode mode) const;

    FILE *logFile() const;

private:
    Log();

private:
    class Private;
    const std::unique_ptr<Private> d;

    Q_DISABLE_COPY(Log)
};

}
