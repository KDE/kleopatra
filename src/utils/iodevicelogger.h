/*
    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2008 Klarälvdalens Datakonsult AB

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#pragma once

#include <QIODevice>

#include <memory>

namespace Kleo
{

class IODeviceLogger : public QIODevice
{
    Q_OBJECT
public:
    explicit IODeviceLogger(const std::shared_ptr<QIODevice> &iod, QObject *parent = nullptr);
    ~IODeviceLogger() override;

    void setWriteLogDevice(const std::shared_ptr<QIODevice> &dev);
    void setReadLogDevice(const std::shared_ptr<QIODevice> &dev);

    bool atEnd() const override;
    qint64 bytesAvailable() const override;
    qint64 bytesToWrite() const override;
    bool canReadLine() const override;
    void close() override;
    bool isSequential() const override;
    bool open(OpenMode mode) override;
    qint64 pos() const override;
    bool reset() override;
    bool seek(qint64 pos) override;
    qint64 size() const override;
    bool waitForBytesWritten(int msecs) override;
    bool waitForReadyRead(int msecs) override;

protected:
    qint64 readData(char *data, qint64 maxSize) override;
    qint64 writeData(const char *data, qint64 maxSize) override;
    qint64 readLineData(char *data, qint64 maxSize) override;

private:
    class Private;
    const std::unique_ptr<Private> d;
};
}
