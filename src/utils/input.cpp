/* -*- mode: c++; c-basic-offset:4 -*-
    utils/input.cpp

    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2007 Klarälvdalens Datakonsult AB

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include <config-kleopatra.h>

#include "input.h"
#include "input_p.h"

#include "cached.h"
#include "detail_p.h"
#include "kdpipeiodevice.h"
#include "kleo_assert.h"
#include "log.h"
#include "windowsprocessdevice.h"

#include <Libkleo/Classify>
#include <Libkleo/KleoException>

#include "kleopatra_debug.h"
#include <KLocalizedString>

#include <QApplication>
#include <QBuffer>
#include <QByteArray>
#include <QClipboard>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QProcess>
#include <QString>

#include <cerrno>

using namespace Kleo;

namespace
{

class PipeInput : public InputImplBase
{
public:
    explicit PipeInput(assuan_fd_t fd);

    std::shared_ptr<QIODevice> ioDevice() const override
    {
        return m_io;
    }
    unsigned int classification() const override;
    unsigned long long size() const override
    {
        return 0;
    }

private:
    std::shared_ptr<QIODevice> m_io;
};

class ProcessStdOutInput : public InputImplBase
{
public:
    ~ProcessStdOutInput() override
    {
        finalize();
    }

    explicit ProcessStdOutInput(const QString &cmd, const QStringList &args, const QDir &wd, const QByteArray &stdin_ = QByteArray());

    std::shared_ptr<QIODevice> ioDevice() const override
    {
        return m_proc;
    }
    unsigned int classification() const override
    {
        return 0U; // plain text
    }
    unsigned long long size() const override
    {
        return 0;
    }
    QString label() const override;
    bool failed() const override;

private:
    QString doErrorString() const override;

private:
    const QString m_command;
    const QStringList m_arguments;
#ifdef Q_OS_WIN
    std::shared_ptr<WindowsProcessDevice> m_proc;
#else
    std::shared_ptr<QProcess> m_proc;
#endif
};

class FileInput : public InputImplBase
{
public:
    explicit FileInput(const QString &fileName);
    explicit FileInput(const std::shared_ptr<QFile> &file);

    QString label() const override
    {
        return m_io ? QFileInfo(m_fileName).fileName() : InputImplBase::label();
    }
    std::shared_ptr<QIODevice> ioDevice() const override
    {
        return m_io;
    }
    unsigned int classification() const override;
    unsigned long long size() const override
    {
        return QFileInfo(m_fileName).size();
    }

private:
    std::shared_ptr<QIODevice> m_io;
    QString m_fileName;
};

#ifndef QT_NO_CLIPBOARD
class ClipboardInput : public Input
{
public:
    explicit ClipboardInput(QClipboard::Mode mode);

    void setLabel(const QString &label) override;
    QString label() const override;
    std::shared_ptr<QIODevice> ioDevice() const override
    {
        return m_buffer;
    }
    unsigned int classification() const override;
    unsigned long long size() const override
    {
        return m_buffer ? m_buffer->buffer().size() : 0;
    }
    QString errorString() const override
    {
        return QString();
    }

private:
    const QClipboard::Mode m_mode;
    std::shared_ptr<QBuffer> m_buffer;
};
#endif // QT_NO_CLIPBOARD

class ByteArrayInput : public Input
{
public:
    explicit ByteArrayInput(QByteArray *data)
        : m_buffer(std::shared_ptr<QBuffer>(new QBuffer(data)))
    {
        if (!m_buffer->open(QIODevice::ReadOnly))
            throw Exception(gpg_error(GPG_ERR_EIO), QStringLiteral("Could not open bytearray for reading?!"));
    }

    void setLabel(const QString &label) override
    {
        m_label = label;
    }
    QString label() const override
    {
        return m_label;
    }
    std::shared_ptr<QIODevice> ioDevice() const override
    {
        return m_buffer;
    }
    unsigned long long size() const override
    {
        return m_buffer ? m_buffer->buffer().size() : 0;
    }
    QString errorString() const override
    {
        return QString();
    }
    unsigned int classification() const override
    {
        return classifyContent(m_buffer->data());
    }

private:
    std::shared_ptr<QBuffer> m_buffer;
    QString m_label;
};

}

std::shared_ptr<Input> Input::createFromByteArray(QByteArray *data, const QString &label)
{
    std::shared_ptr<ByteArrayInput> po(new ByteArrayInput(data));
    po->setLabel(label);
    return po;
}

std::shared_ptr<Input> Input::createFromPipeDevice(assuan_fd_t fd, const QString &label)
{
    std::shared_ptr<PipeInput> po(new PipeInput(fd));
    po->setDefaultLabel(label);
    return po;
}

PipeInput::PipeInput(assuan_fd_t fd)
    : InputImplBase()
    , m_io()
{
    std::shared_ptr<KDPipeIODevice> kdp(new KDPipeIODevice);
    errno = 0;
    if (!kdp->open(fd, QIODevice::ReadOnly))
        throw Exception(errno ? gpg_error_from_errno(errno) : gpg_error(GPG_ERR_EIO), i18n("Could not open FD %1 for reading", _detail::assuanFD2int(fd)));
    m_io = Log::instance()->createIOLogger(kdp, QStringLiteral("pipe-input"), Log::Read);
}

unsigned int PipeInput::classification() const
{
    notImplemented();
    return 0;
}

std::shared_ptr<Input> Input::createFromFile(const QString &fileName, bool)
{
    return std::shared_ptr<Input>(new FileInput(fileName));
}

std::shared_ptr<Input> Input::createFromFile(const std::shared_ptr<QFile> &file)
{
    return std::shared_ptr<Input>(new FileInput(file));
}

FileInput::FileInput(const QString &fileName)
    : InputImplBase()
    , m_io()
    , m_fileName(fileName)
{
    std::shared_ptr<QFile> file(new QFile(fileName));

    errno = 0;
    if (!file->open(QIODevice::ReadOnly))
        throw Exception(errno ? gpg_error_from_errno(errno) : gpg_error(GPG_ERR_EIO), i18n("Could not open file \"%1\" for reading", fileName));
    m_io = Log::instance()->createIOLogger(file, QStringLiteral("file-in"), Log::Read);
}

FileInput::FileInput(const std::shared_ptr<QFile> &file)
    : InputImplBase()
    , m_io()
    , m_fileName(file->fileName())
{
    kleo_assert(file);
    errno = 0;
    if (file->isOpen() && !file->isReadable())
        throw Exception(gpg_error(GPG_ERR_INV_ARG), i18n("File \"%1\" is already open, but not for reading", file->fileName()));
    if (!file->isOpen() && !file->open(QIODevice::ReadOnly))
        throw Exception(errno ? gpg_error_from_errno(errno) : gpg_error(GPG_ERR_EIO), i18n("Could not open file \"%1\" for reading", m_fileName));
    m_io = Log::instance()->createIOLogger(file, QStringLiteral("file-in"), Log::Read);
}

unsigned int FileInput::classification() const
{
    return classify(m_fileName);
}

std::shared_ptr<Input> Input::createFromProcessStdOut(const QString &command, const QStringList &args, const QDir &wd)
{
    return std::shared_ptr<Input>(new ProcessStdOutInput(command, args, wd));
}

std::shared_ptr<Input> Input::createFromProcessStdOut(const QString &command, const QStringList &args, const QDir &wd, const QByteArray &stdin_)
{
    return std::shared_ptr<Input>(new ProcessStdOutInput(command, args, wd, stdin_));
}

namespace
{
struct Outputter {
    const QByteArray &data;
    explicit Outputter(const QByteArray &data)
        : data(data)
    {
    }
};
static QDebug operator<<(QDebug s, const Outputter &o)
{
    if (const quint64 size = o.data.size()) {
        s << " << (" << size << "bytes)";
    }
    return s;
}
}

ProcessStdOutInput::ProcessStdOutInput(const QString &cmd, const QStringList &args, const QDir &wd, const QByteArray &stdin_)
    : InputImplBase()
    , m_command(cmd)
    , m_arguments(args)
{
    const QIODevice::OpenMode openMode = stdin_.isEmpty() ? QIODevice::ReadOnly : QIODevice::ReadWrite;
    qCDebug(KLEOPATRA_LOG) << "cd" << wd.absolutePath() << '\n' << cmd << args << Outputter(stdin_);
    if (cmd.isEmpty())
        throw Exception(gpg_error(GPG_ERR_INV_ARG), i18n("Command not specified"));

#ifndef Q_OS_WIN
    m_proc = std::shared_ptr<QProcess>(new QProcess);
    m_proc->setWorkingDirectory(wd.absolutePath());
    m_proc->start(cmd, args, openMode);
    if (!m_proc->waitForStarted())
        throw Exception(gpg_error(GPG_ERR_EIO), i18n("Could not start %1 process: %2", cmd, m_proc->errorString()));
#else
    m_proc = std::shared_ptr<Kleo::WindowsProcessDevice>(new WindowsProcessDevice(cmd, args, wd.absolutePath()));
    if (!m_proc->open(openMode)) {
        throw Exception(gpg_error(GPG_ERR_EIO), i18n("Could not start %1 process: %2", cmd, m_proc->errorString()));
    }
#endif
    if (!stdin_.isEmpty()) {
        if (m_proc->write(stdin_) != stdin_.size())
            throw Exception(gpg_error(GPG_ERR_EIO), i18n("Failed to write input to %1 process: %2", cmd, m_proc->errorString()));
        m_proc->closeWriteChannel();
    }
}

QString ProcessStdOutInput::label() const
{
    if (!m_proc) {
        return InputImplBase::label();
    }
    // output max. 3 arguments
    const QString cmdline = (QStringList(m_command) + m_arguments.mid(0, 3)).join(QLatin1Char(' '));
    if (m_arguments.size() > 3) {
        return i18nc("e.g. \"Output of tar xf - file1 ...\"", "Output of %1 ...", cmdline);
    } else {
        return i18nc("e.g. \"Output of tar xf - file\"", "Output of %1", cmdline);
    }
}

QString ProcessStdOutInput::doErrorString() const
{
    kleo_assert(m_proc);
#ifdef Q_OS_WIN
    const auto err = m_proc->errorString();
    if (!err.isEmpty()) {
        return QStringLiteral("%1:\n%2").arg(m_command).arg(err);
    }
    return QString();
#else
    if (m_proc->exitStatus() == QProcess::NormalExit && m_proc->exitCode() == 0) {
        return QString();
    }
    if (m_proc->error() == QProcess::UnknownError)
        return i18n("Error while running %1:\n%2", m_command, QString::fromLocal8Bit(m_proc->readAllStandardError().trimmed().constData()));
    else {
        return i18n("Failed to execute %1: %2", m_command, m_proc->errorString());
    }
#endif
}

bool ProcessStdOutInput::failed() const
{
    kleo_assert(m_proc);
#ifdef Q_OS_WIN
    return !m_proc->errorString().isEmpty();
#else
    return !(m_proc->exitStatus() == QProcess::NormalExit && m_proc->exitCode() == 0);
#endif
}

#ifndef QT_NO_CLIPBOARD
std::shared_ptr<Input> Input::createFromClipboard()
{
    return std::shared_ptr<Input>(new ClipboardInput(QClipboard::Clipboard));
}

static QByteArray dataFromClipboard(QClipboard::Mode mode)
{
    Q_UNUSED(mode)
    if (QClipboard *const cb = QApplication::clipboard()) {
        return cb->text().toUtf8();
    } else {
        return QByteArray();
    }
}

ClipboardInput::ClipboardInput(QClipboard::Mode mode)
    : Input()
    , m_mode(mode)
    , m_buffer(new QBuffer)
{
    m_buffer->setData(dataFromClipboard(mode));
    if (!m_buffer->open(QIODevice::ReadOnly))
        throw Exception(gpg_error(GPG_ERR_EIO), i18n("Could not open clipboard for reading"));
}

void ClipboardInput::setLabel(const QString &)
{
    notImplemented();
}

QString ClipboardInput::label() const
{
    switch (m_mode) {
    case QClipboard::Clipboard:
        return i18n("Clipboard contents");
    case QClipboard::FindBuffer:
        return i18n("FindBuffer contents");
    case QClipboard::Selection:
        return i18n("Current selection");
    };
    return QString();
}

unsigned int ClipboardInput::classification() const
{
    return classifyContent(m_buffer->data());
}
#endif // QT_NO_CLIPBOARD

Input::~Input()
{
}

void Input::finalize()
{
    if (const std::shared_ptr<QIODevice> io = ioDevice())
        if (io->isOpen()) {
            qCDebug(KLEOPATRA_LOG) << "closing input";
            io->close();
        }
}
