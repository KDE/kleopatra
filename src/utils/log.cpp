/*
    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2008 Klarälvdalens Datakonsult AB

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include <config-kleopatra.h>

#include "log.h"

#include "iodevicelogger.h"

#include <Libkleo/KleoException>

#include <KLocalizedString>
#include <KRandom>

#include <QDateTime>
#include <QDir>
#include <QFile>
#include <QString>

using namespace Kleo;

class Log::Private
{
    Log *const q;

public:
    explicit Private(Log *qq)
        : q(qq)
        , m_ioLoggingEnabled(false)
        , m_logFile(nullptr)
    {
        Q_UNUSED(q);
    }
    ~Private();
    bool m_ioLoggingEnabled;
    QString m_outputDirectory;
    FILE *m_logFile;
};

Log::Private::~Private()
{
    if (m_logFile) {
        fclose(m_logFile);
    }
}

void Log::messageHandler(QtMsgType type, const QMessageLogContext &ctx, const QString &msg)
{
    const QString formattedMessage = qFormatLogMessage(type, ctx, msg);
    const QByteArray local8str = formattedMessage.toLocal8Bit();
    FILE *const file = Log::instance()->logFile();
    if (!file) {
        fprintf(stderr, "Log::messageHandler[!file]: %s", local8str.constData());
        return;
    }

    qint64 toWrite = local8str.size();
    while (toWrite > 0) {
        const qint64 written = fprintf(file, "%s", local8str.constData());
        if (written == -1) {
            return;
        }
        toWrite -= written;
    }
    // append newline:
    while (fprintf(file, "\n") == 0)
        ;
    fflush(file);
}

std::shared_ptr<const Log> Log::instance()
{
    return mutableInstance();
}

std::shared_ptr<Log> Log::mutableInstance()
{
    static std::weak_ptr<Log> self;
    try {
        return std::shared_ptr<Log>(self);
    } catch (const std::bad_weak_ptr &) {
        const std::shared_ptr<Log> s(new Log);
        self = s;
        return s;
    }
}

Log::Log()
    : d(new Private(this))
{
}

Log::~Log()
{
}

FILE *Log::logFile() const
{
    return d->m_logFile;
}

void Log::setIOLoggingEnabled(bool enabled)
{
    d->m_ioLoggingEnabled = enabled;
}

bool Log::ioLoggingEnabled() const
{
    return d->m_ioLoggingEnabled;
}

QString Log::outputDirectory() const
{
    return d->m_outputDirectory;
}

void Log::setOutputDirectory(const QString &path)
{
    if (d->m_outputDirectory == path) {
        return;
    }
    d->m_outputDirectory = path;
    Q_ASSERT(!d->m_logFile);
    const QString lfn = path + QLatin1StringView("/kleo-log");
    d->m_logFile = fopen(QDir::toNativeSeparators(lfn).toLocal8Bit().constData(), "a");
    Q_ASSERT(d->m_logFile);
}

std::shared_ptr<QIODevice> Log::createIOLogger(const std::shared_ptr<QIODevice> &io, const QString &prefix, OpenMode mode) const
{
    if (!d->m_ioLoggingEnabled) {
        return io;
    }

    std::shared_ptr<IODeviceLogger> logger(new IODeviceLogger(io));

    const QString timestamp = QDateTime::currentDateTime().toString(QStringLiteral("yyMMdd-hhmmss"));

    const QString fn = d->m_outputDirectory + QLatin1Char('/') + prefix + QLatin1Char('-') + timestamp + QLatin1Char('-') + KRandom::randomString(4);
    std::shared_ptr<QFile> file(new QFile(fn));

    if (!file->open(QIODevice::WriteOnly)) {
        throw Exception(gpg_error(GPG_ERR_EIO), i18n("Log Error: Could not open log file \"%1\" for writing.", fn));
    }

    if (mode & Read) {
        logger->setReadLogDevice(file);
    } else { // Write
        logger->setWriteLogDevice(file);
    }

    return logger;
}
