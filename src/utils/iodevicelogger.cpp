/* -*- mode: c++; c-basic-offset:4 -*-
    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2008 Klarälvdalens Datakonsult AB

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include <config-kleopatra.h>

#include "iodevicelogger.h"

using namespace Kleo;

class IODeviceLogger::Private
{
    IODeviceLogger *const q;

public:
    static bool write(const std::shared_ptr<QIODevice> &dev, const char *data, qint64 max);

    explicit Private(const std::shared_ptr<QIODevice> &io_, IODeviceLogger *qq)
        : q(qq)
        , io(io_)
        , writeLog()
        , readLog()
    {
        Q_ASSERT(io);
        connect(io.get(), &QIODevice::aboutToClose, q, &QIODevice::aboutToClose);
        connect(io.get(), &QIODevice::bytesWritten, q, &QIODevice::bytesWritten);
        connect(io.get(), &QIODevice::readyRead, q, &QIODevice::readyRead);
        q->setOpenMode(io->openMode());
    }

    ~Private()
    {
    }

    const std::shared_ptr<QIODevice> io;
    std::shared_ptr<QIODevice> writeLog;
    std::shared_ptr<QIODevice> readLog;
};

bool IODeviceLogger::Private::write(const std::shared_ptr<QIODevice> &dev, const char *data, qint64 max)
{
    Q_ASSERT(dev);
    Q_ASSERT(data);
    Q_ASSERT(max >= 0);
    qint64 toWrite = max;
    while (toWrite > 0) {
        const qint64 written = dev->write(data, toWrite);
        if (written < 0) {
            return false;
        }
        toWrite -= written;
    }
    return true;
}

IODeviceLogger::IODeviceLogger(const std::shared_ptr<QIODevice> &iod, QObject *parent)
    : QIODevice(parent)
    , d(new Private(iod, this))
{
}

IODeviceLogger::~IODeviceLogger()
{
}

void IODeviceLogger::setWriteLogDevice(const std::shared_ptr<QIODevice> &dev)
{
    d->writeLog = dev;
}

void IODeviceLogger::setReadLogDevice(const std::shared_ptr<QIODevice> &dev)
{
    d->readLog = dev;
}

bool IODeviceLogger::atEnd() const
{
    return d->io->atEnd();
}

qint64 IODeviceLogger::bytesAvailable() const
{
    return d->io->bytesAvailable();
}

qint64 IODeviceLogger::bytesToWrite() const
{
    return d->io->bytesToWrite();
}

bool IODeviceLogger::canReadLine() const
{
    return d->io->canReadLine();
}

void IODeviceLogger::close()
{
    d->io->close();
}

bool IODeviceLogger::isSequential() const
{
    return d->io->isSequential();
}

bool IODeviceLogger::open(OpenMode mode)
{
    QIODevice::open(mode);
    return d->io->open(mode);
}

qint64 IODeviceLogger::pos() const
{
    return d->io->pos();
}

bool IODeviceLogger::reset()
{
    return d->io->reset();
}

bool IODeviceLogger::seek(qint64 pos)
{
    return d->io->seek(pos);
}

qint64 IODeviceLogger::size() const
{
    return d->io->size();
}

bool IODeviceLogger::waitForBytesWritten(int msecs)
{
    return d->io->waitForBytesWritten(msecs);
}

bool IODeviceLogger::waitForReadyRead(int msecs)
{
    return d->io->waitForReadyRead(msecs);
}

qint64 IODeviceLogger::readData(char *data, qint64 maxSize)
{
    const qint64 num = d->io->read(data, maxSize);
    if (num > 0 && d->readLog) {
        Private::write(d->readLog, data, num);
    }
    return num;
}

qint64 IODeviceLogger::writeData(const char *data, qint64 maxSize)
{
    const qint64 num = d->io->write(data, maxSize);
    if (num > 0 && d->writeLog) {
        Private::write(d->writeLog, data, num);
    }
    return num;
}

qint64 IODeviceLogger::readLineData(char *data, qint64 maxSize)
{
    const qint64 num = d->io->readLine(data, maxSize);
    if (num > 0 && d->readLog) {
        Private::write(d->readLog, data, num);
    }
    return num;
}

#include "moc_iodevicelogger.cpp"
