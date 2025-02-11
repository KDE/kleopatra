/*
    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2019 g 10code GmbH

    SPDX-License-Identifier: GPL-2.0-or-later
 */

#if defined(WIN32) || defined(Q_MOC_RUN)
#ifndef WINDOWSPROCESSDEVICE_H
#define WINDOWSPROCESSDEVICE_H

#include <memory>

#include <QIODevice>

class QString;
#include <QStringList>

namespace Kleo
{
/* Simplistic anonymous pipe io device
 *
 * Create an IODevice using Windows Create Process and pipes
 * this class serves as an alternative to use QProcess on
 * Windows which event driven nature does not play well
 * in our threading and IPC model.
 *
 * This class was written with gpgtar in mind and mostly
 * a reaction to multiple issues we had with QProcess
 * and gpgtar in GPGME on Windows. It was so hard to debug them
 * that we decided for a simple approach that gives us
 * full control.
 *
 * As there are use cases streaming terrabytes through this
 * even the control of the buffer size is an advantage.
 *
 **/
class WindowsProcessDevice : public QIODevice
{
    Q_OBJECT
public:
    WindowsProcessDevice(const QString &path, const QStringList &args, const QString &wd);

    /* Starts the process. Only supports
       QIODevice::ReadOnly
       QIODevice::WriteOnly
       QIODevice::ReadWrite */
    bool open(OpenMode mode) override;

    /* Terminates the process */
    void close() override;

    bool isSequential() const override;

    /* Closes the write channel */
    void closeWriteChannel();

    /* Get the an error string either stderr or a windows error */
    QString errorString();

protected:
    /* Blocking read */
    qint64 readData(char *data, qint64 maxSize) override;
    /* Blocking write */
    qint64 writeData(const char *data, qint64 size) override;

private:
    Q_DISABLE_COPY(WindowsProcessDevice)
    class Private;
    std::shared_ptr<Private> d;
};

} // namespace Kleo

#endif // WINDOWSPROCESSDEVICE_H
#endif // WIN32
