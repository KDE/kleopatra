/*
    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2007 Klarälvdalens Datakonsult AB

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include <config-kleopatra.h>

#include "output.h"

#include "cached.h"
#include "detail_p.h"
#include "input_p.h"
#include "kdpipeiodevice.h"
#include "kleo_assert.h"
#include "log.h"
#include "overwritedialog.h"

#include <Libkleo/KleoException>

#include <KFileUtils>
#include <KLocalizedString>
#include <KMessageBox>

#include "kleopatra_debug.h"

#include <QApplication>
#include <QBuffer>
#include <QClipboard>
#include <QDir>
#include <QFileInfo>
#include <QPointer>
#include <QProcess>
#include <QString>
#include <QTemporaryFile>
#include <QTimer>
#include <QUrl>
#include <QWidget>

#ifdef Q_OS_WIN
#include <windows.h>
#endif

#include <cerrno>

using namespace Kleo;
using namespace Kleo::_detail;

static const int PROCESS_MAX_RUNTIME_TIMEOUT = -1; // no timeout
static const int PROCESS_TERMINATE_TIMEOUT = 5 * 1000; // 5s

class OverwritePolicy::Private
{
public:
    Private(QWidget *p, OverwritePolicy::Options options_, OverwritePolicy::Policy pol)
        : policy(pol)
        , parentWidget(p)
        , options{options_}
    {
    }

    OverwritePolicy::Policy policy;
    QWidget *parentWidget;
    OverwritePolicy::Options options;
};

OverwritePolicy::OverwritePolicy(Policy initialPolicy)
    : d{new Private{nullptr, {}, initialPolicy}}
{
}

OverwritePolicy::OverwritePolicy(QWidget *parent, OverwritePolicy::Options options)
    : d{new Private{parent, options, Ask}}
{
}

OverwritePolicy::~OverwritePolicy() = default;

OverwritePolicy::Policy OverwritePolicy::policy() const
{
    return d->policy;
}

void OverwritePolicy::setPolicy(Policy policy)
{
    d->policy = policy;
}

namespace
{

class TemporaryFile : public QTemporaryFile
{
public:
    using QTemporaryFile::QTemporaryFile;

    void close() override
    {
        if (isOpen()) {
            m_oldFileName = fileName();
        }
        QTemporaryFile::close();
    }

    bool openNonInheritable()
    {
        if (!QTemporaryFile::open()) {
            return false;
        }
#if defined(Q_OS_WIN)
        // QTemporaryFile (tested with 4.3.3) creates the file handle as inheritable.
        // The handle is then inherited by gpgsm, which prevents deletion of the temp file
        // in FileOutput::doFinalize()
        // There are no inheritable handles under wince
        return SetHandleInformation((HANDLE)_get_osfhandle(handle()), HANDLE_FLAG_INHERIT, 0);
#endif
        return true;
    }

    QString oldFileName() const
    {
        return m_oldFileName;
    }

private:
    QString m_oldFileName;
};

template<typename T_IODevice>
struct inhibit_close : T_IODevice {
    explicit inhibit_close()
        : T_IODevice()
    {
    }
    template<typename T1>
    explicit inhibit_close(T1 &t1)
        : T_IODevice(t1)
    {
    }

    /* reimp */ void close() override
    {
    }
    void reallyClose()
    {
        T_IODevice::close();
    }
};

template<typename T_IODevice>
struct redirect_close : T_IODevice {
    explicit redirect_close()
        : T_IODevice()
        , m_closed(false)
    {
    }
    template<typename T1>
    explicit redirect_close(T1 &t1)
        : T_IODevice(t1)
        , m_closed(false)
    {
    }

    /* reimp */ void close() override
    {
        this->closeWriteChannel();
        m_closed = true;
    }

    bool isClosed() const
    {
        return m_closed;
    }

private:
    bool m_closed;
};

class FileOutput;
class OutputInput : public InputImplBase
{
public:
    OutputInput(const std::shared_ptr<FileOutput> &output);

    unsigned int classification() const override
    {
        return 0;
    }

    void outputFinalized()
    {
        if (!m_ioDevice->open(QIODevice::ReadOnly)) {
            qCCritical(KLEOPATRA_LOG) << "Failed to open file for reading";
        }
    }

    std::shared_ptr<QIODevice> ioDevice() const override
    {
        return m_ioDevice;
    }

    unsigned long long size() const override
    {
        return 0;
    }

    QString label() const override;

private:
    std::shared_ptr<FileOutput> m_output;
    mutable std::shared_ptr<QIODevice> m_ioDevice = nullptr;
};

class OutputImplBase : public Output
{
public:
    OutputImplBase()
        : Output()
        , m_defaultLabel()
        , m_customLabel()
        , m_errorString()
        , m_isFinalized(false)
        , m_isFinalizing(false)
        , m_cancelPending(false)
        , m_canceled(false)
        , m_binaryOpt(false)
    {
    }

    QString label() const override
    {
        return m_customLabel.isEmpty() ? m_defaultLabel : m_customLabel;
    }
    void setLabel(const QString &label) override
    {
        m_customLabel = label;
    }
    void setDefaultLabel(const QString &l)
    {
        m_defaultLabel = l;
    }
    void setBinaryOpt(bool value) override
    {
        m_binaryOpt = value;
    }
    bool binaryOpt() const override
    {
        return m_binaryOpt;
    }

    QString errorString() const override
    {
        if (m_errorString.dirty()) {
            m_errorString = doErrorString();
        }
        return m_errorString;
    }

    bool isFinalized() const override
    {
        return m_isFinalized;
    }
    void finalize() override
    {
        qCDebug(KLEOPATRA_LOG) << this;
        if (m_isFinalized || m_isFinalizing) {
            return;
        }
        m_isFinalizing = true;
        try {
            doFinalize();
        } catch (...) {
            m_isFinalizing = false;
            throw;
        }
        m_isFinalizing = false;
        m_isFinalized = true;
        if (m_cancelPending) {
            cancel();
        }
    }

    void cancel() override
    {
        qCDebug(KLEOPATRA_LOG) << this;
        if (m_isFinalizing) {
            m_cancelPending = true;
        } else if (!m_canceled) {
            m_isFinalizing = true;
            try {
                doCancel();
            } catch (...) {
            }
            m_isFinalizing = false;
            m_isFinalized = false;
            m_canceled = true;
        }
    }

private:
    virtual QString doErrorString() const
    {
        if (std::shared_ptr<QIODevice> io = ioDevice()) {
            return io->errorString();
        } else {
            return i18n("No output device");
        }
    }
    virtual void doFinalize() = 0;
    virtual void doCancel() = 0;

private:
    QString m_defaultLabel;
    QString m_customLabel;
    mutable cached<QString> m_errorString;
    bool m_isFinalized : 1;
    bool m_isFinalizing : 1;
    bool m_cancelPending : 1;
    bool m_canceled : 1;
    bool m_binaryOpt : 1;
};

class PipeOutput : public OutputImplBase
{
public:
    explicit PipeOutput(assuan_fd_t fd);

    std::shared_ptr<QIODevice> ioDevice() const override
    {
        return m_io;
    }
    void doFinalize() override
    {
        m_io->reallyClose();
    }
    void doCancel() override
    {
        doFinalize();
    }

private:
    std::shared_ptr<inhibit_close<KDPipeIODevice>> m_io;
};

class ProcessStdInOutput : public OutputImplBase
{
public:
    explicit ProcessStdInOutput(const QString &cmd, const QStringList &args, const QDir &wd, const QString &file);

    std::shared_ptr<QIODevice> ioDevice() const override
    {
        return m_proc;
    }
    void doFinalize() override
    {
        /*
          Make sure the data is written in the output here. If this
          is not done the output will be written in small chunks
          trough the eventloop causing an unnecessary delay before
          the process has even a chance to work and finish.
          This delay is mainly noticeable on Windows where it can
          take ~30 seconds to write out a 10MB file in the 512 byte
          chunks gpgme serves. */
        qCDebug(KLEOPATRA_LOG) << "Waiting for " << m_proc->bytesToWrite() << " Bytes to be written";
        while (m_proc->waitForBytesWritten(PROCESS_MAX_RUNTIME_TIMEOUT))
            ;

        if (!m_proc->isClosed()) {
            m_proc->close();
        }
        m_proc->waitForFinished(PROCESS_MAX_RUNTIME_TIMEOUT);
    }

    bool failed() const override
    {
        if (!m_proc) {
            return false;
        }
        return !(m_proc->exitStatus() == QProcess::NormalExit && m_proc->exitCode() == 0);
    }

    void doCancel() override
    {
        m_proc->terminate();
        QTimer::singleShot(PROCESS_TERMINATE_TIMEOUT, m_proc.get(), &QProcess::kill);
    }
    QString label() const override;

private:
    QString doErrorString() const override;

private:
    const QString m_command;
    const QStringList m_arguments;
    const std::shared_ptr<redirect_close<QProcess>> m_proc;
    const QString m_file;
};

class FileOutput : public OutputImplBase
{
public:
    explicit FileOutput(const QString &fileName, const std::shared_ptr<OverwritePolicy> &policy);
    ~FileOutput() override
    {
        qCDebug(KLEOPATRA_LOG) << this;
    }

    QString label() const override
    {
        return QFileInfo(m_fileName).fileName();
    }
    std::shared_ptr<QIODevice> ioDevice() const override
    {
        return m_tmpFile;
    }
    void doFinalize() override;
    void doCancel() override
    {
        qCDebug(KLEOPATRA_LOG) << this;
    }
    QString fileName() const override
    {
        return m_fileName;
    }

    void attachInput(const std::shared_ptr<OutputInput> &input)
    {
        m_attachedInput = std::weak_ptr<OutputInput>(input);
    }

private:
    QString m_fileName;
    std::shared_ptr<TemporaryFile> m_tmpFile;
    const std::shared_ptr<OverwritePolicy> m_policy;
    std::weak_ptr<OutputInput> m_attachedInput;
};

#ifndef QT_NO_CLIPBOARD
class ClipboardOutput : public OutputImplBase
{
public:
    explicit ClipboardOutput(QClipboard::Mode mode);

    QString label() const override;
    std::shared_ptr<QIODevice> ioDevice() const override
    {
        return m_buffer;
    }
    void doFinalize() override;
    void doCancel() override
    {
    }

private:
    QString doErrorString() const override
    {
        return QString();
    }

private:
    const QClipboard::Mode m_mode;
    std::shared_ptr<QBuffer> m_buffer;
};
#endif // QT_NO_CLIPBOARD

class ByteArrayOutput : public OutputImplBase
{
public:
    explicit ByteArrayOutput(QByteArray *data)
        : m_buffer(std::shared_ptr<QBuffer>(new QBuffer(data)))
    {
        if (!m_buffer->open(QIODevice::WriteOnly))
            throw Exception(gpg_error(GPG_ERR_EIO), QStringLiteral("Could not open bytearray for writing?!"));
    }

    QString label() const override
    {
        return m_label;
    }

    void setLabel(const QString &label) override
    {
        m_label = label;
    }

    std::shared_ptr<QIODevice> ioDevice() const override
    {
        return m_buffer;
    }

    void doFinalize() override
    {
        m_buffer->close();
    }

    void doCancel() override
    {
        m_buffer->close();
    }

private:
    QString doErrorString() const override
    {
        return QString();
    }

private:
    QString m_label;
    std::shared_ptr<QBuffer> m_buffer;
};

}

std::shared_ptr<Output> Output::createFromPipeDevice(assuan_fd_t fd, const QString &label)
{
    std::shared_ptr<PipeOutput> po(new PipeOutput(fd));
    po->setDefaultLabel(label);
    return po;
}

PipeOutput::PipeOutput(assuan_fd_t fd)
    : OutputImplBase()
    , m_io(new inhibit_close<KDPipeIODevice>)
{
    errno = 0;
    if (!m_io->open(fd, QIODevice::WriteOnly))
        throw Exception(errno ? gpg_error_from_errno(errno) : gpg_error(GPG_ERR_EIO), i18n("Could not open FD %1 for writing", assuanFD2int(fd)));
}

std::shared_ptr<Output> Output::createFromFile(const QString &fileName, bool forceOverwrite)
{
    return createFromFile(fileName, std::make_shared<OverwritePolicy>(forceOverwrite ? OverwritePolicy::Overwrite : OverwritePolicy::Skip));
}

std::shared_ptr<Output> Output::createFromFile(const QString &fileName, const std::shared_ptr<OverwritePolicy> &policy)
{
    std::shared_ptr<FileOutput> fo(new FileOutput(fileName, policy));
    qCDebug(KLEOPATRA_LOG) << fo.get();
    return fo;
}

FileOutput::FileOutput(const QString &fileName, const std::shared_ptr<OverwritePolicy> &policy)
    : OutputImplBase()
    , m_fileName(fileName)
    , m_tmpFile(new TemporaryFile(fileName))
    , m_policy(policy)
{
    Q_ASSERT(m_policy);
    errno = 0;
    if (!m_tmpFile->openNonInheritable())
        throw Exception(errno ? gpg_error_from_errno(errno) : gpg_error(GPG_ERR_EIO), i18n("Could not create temporary file for output \"%1\"", fileName));
}

static QString suggestFileName(const QString &fileName)
{
    const QFileInfo fileInfo{fileName};
    const QString path = fileInfo.absolutePath();
    const QString newFileName = KFileUtils::suggestName(QUrl::fromLocalFile(path), fileInfo.fileName());
    return path + QLatin1Char{'/'} + newFileName;
}

OverwritePolicy::PolicyAndFileName OverwritePolicy::obtainOverwritePermission(const QString &fileName, Options extraOptions)
{
    switch (d->policy) {
    case OverwritePolicy::None:
        // shouldn't happen, but treat it as Ask
    case OverwritePolicy::Ask:
        break;
    case OverwritePolicy::Append:
    case OverwritePolicy::Overwrite:
        return {d->policy, fileName};
    case OverwritePolicy::Rename: {
        return {d->policy, suggestFileName(fileName)};
    }
    case OverwritePolicy::Skip:
        return {d->policy, {}};
    case OverwritePolicy::Cancel:
        qCDebug(KLEOPATRA_LOG) << __func__ << "Error: Called although user canceled operation";
        return {d->policy, {}};
    }

    OverwriteDialog::Options options = OverwriteDialog::AllowRename;
    if (d->options & MultipleFiles) {
        options |= OverwriteDialog::MultipleItems | OverwriteDialog::AllowSkip;
    }
    if (extraOptions & AllowAppend) {
        options |= OverwriteDialog::AllowAppend;
    }
    OverwriteDialog dialog{d->parentWidget, i18nc("@title:window", "File Already Exists"), fileName, options};
    const auto result = static_cast<OverwriteDialog::Result>(dialog.exec());
    qCDebug(KLEOPATRA_LOG) << __func__ << "result:" << static_cast<int>(result);
    switch (result) {
    case OverwriteDialog::Cancel:
        d->policy = OverwritePolicy::Cancel;
        return {OverwritePolicy::Cancel, {}};
    case OverwriteDialog::AutoSkip:
        d->policy = OverwritePolicy::Skip;
        [[fallthrough]];
    case OverwriteDialog::Skip:
        return {OverwritePolicy::Skip, {}};
    case OverwriteDialog::Append:
        return {OverwritePolicy::Append, fileName};
    case OverwriteDialog::OverwriteAll:
        d->policy = OverwritePolicy::Overwrite;
        [[fallthrough]];
    case OverwriteDialog::Overwrite:
        return {OverwritePolicy::Overwrite, fileName};
    case OverwriteDialog::Rename:
        return {OverwritePolicy::Rename, dialog.newFileName()};
    case OverwriteDialog::AutoRename: {
        d->policy = OverwritePolicy::Rename;
        return {OverwritePolicy::Rename, suggestFileName(fileName)};
    }
    };
    qCDebug(KLEOPATRA_LOG) << __func__ << "unexpected result:" << result;
    return {OverwritePolicy::None, {}};
}

void FileOutput::doFinalize()
{
    qCDebug(KLEOPATRA_LOG) << this;

    struct Remover {
        QString file;
        ~Remover()
        {
            if (QFile::exists(file)) {
                QFile::remove(file);
            }
        }
    } remover;

    kleo_assert(m_tmpFile);

    if (m_tmpFile->isOpen()) {
        m_tmpFile->close();
    }

    QString tmpFileName = m_tmpFile->oldFileName();
    remover.file = tmpFileName;

    m_tmpFile->setAutoRemove(false);
    QPointer<QObject> guard = m_tmpFile.get();
    m_tmpFile.reset(); // really close the file - needed on Windows for renaming :/
    kleo_assert(!guard); // if this triggers, we need to audit for holder of std::shared_ptr<QIODevice>s.

    const QFileInfo fi(tmpFileName);
    if (!fi.exists()) {
        /* QT Bug 83365 since qt 5.13 causes the filename of temporary files
         * in UNC path name directories (unmounted samba shares) to start with
         * UNC/ instead of the // that Qt can actually handle for things like
         * rename and remove. So if we can't find our temporary file we try
         * to workaround that bug. */
        qCDebug(KLEOPATRA_LOG) << "failure to find " << tmpFileName;
        if (tmpFileName.startsWith(QLatin1StringView("UNC"))) {
            tmpFileName.replace(0, strlen("UNC"), QLatin1Char('/'));
            remover.file = tmpFileName;
        }
        const QFileInfo fi2(tmpFileName);
        if (!fi2.exists()) {
            throw Exception(gpg_error(GPG_ERR_EIO), QStringLiteral("Could not find temporary file \"%1\".").arg(tmpFileName));
        }
    }

    qCDebug(KLEOPATRA_LOG) << this << "renaming" << tmpFileName << "->" << m_fileName;
    if (QFile::rename(tmpFileName, m_fileName)) {
        qCDebug(KLEOPATRA_LOG) << this << "renaming succeeded";

        if (!m_attachedInput.expired()) {
            m_attachedInput.lock()->outputFinalized();
        }
        return;
    }

    qCDebug(KLEOPATRA_LOG) << this << "renaming failed";

    if (QFile::exists(m_fileName)) {
        const auto policyAndFileName = m_policy->obtainOverwritePermission(m_fileName);
        switch (policyAndFileName.policy) {
        case OverwritePolicy::Cancel:
            throw Exception(gpg_error(GPG_ERR_CANCELED), i18n("Overwriting declined"));
        case OverwritePolicy::Overwrite: {
            qCDebug(KLEOPATRA_LOG) << this << "going to remove file for overwriting" << m_fileName;
            if (!QFile::remove(m_fileName)) {
                throw Exception(errno ? gpg_error_from_errno(errno) : gpg_error(GPG_ERR_EIO),
                                xi18nc("@info", "Could not remove file <filename>%1</filename> for overwriting.", m_fileName));
            }
            qCDebug(KLEOPATRA_LOG) << this << "removing file to overwrite succeeded";
            break;
        }
        case OverwritePolicy::Rename: {
            m_fileName = policyAndFileName.fileName;
            break;
        }
        case OverwritePolicy::None:
        case OverwritePolicy::Ask:
        case OverwritePolicy::Append:
        case OverwritePolicy::Skip:
            qCDebug(KLEOPATRA_LOG) << "Unexpected OverwritePolicy result" << policyAndFileName.policy << "for" << m_fileName;
        };
    }

    qCDebug(KLEOPATRA_LOG) << this << "renaming" << tmpFileName << "->" << m_fileName;
    if (QFile::rename(tmpFileName, m_fileName)) {
        qCDebug(KLEOPATRA_LOG) << this << "renaming succeeded";

        if (!m_attachedInput.expired()) {
            m_attachedInput.lock()->outputFinalized();
        }
        return;
    }

    qCDebug(KLEOPATRA_LOG) << this << "renaming failed";

    throw Exception(errno ? gpg_error_from_errno(errno) : gpg_error(GPG_ERR_EIO), i18n(R"(Could not rename file "%1" to "%2")", tmpFileName, m_fileName));
}


std::shared_ptr<Output> Output::createFromProcessStdIn(const QString &command, const QStringList &args, const QDir &wd, const QString &file)
{
    return std::shared_ptr<Output>(new ProcessStdInOutput(command, args, wd, file));
}

ProcessStdInOutput::ProcessStdInOutput(const QString &cmd, const QStringList &args, const QDir &wd, const QString &file)
    : OutputImplBase()
    , m_command(cmd)
    , m_arguments(args)
    , m_proc(new redirect_close<QProcess>)
    , m_file(file)
{
    qCDebug(KLEOPATRA_LOG) << "cd" << wd.absolutePath() << '\n' << cmd << args;
    if (cmd.isEmpty())
        throw Exception(gpg_error(GPG_ERR_INV_ARG), i18n("Command not specified"));
    m_proc->setWorkingDirectory(wd.absolutePath());
    m_proc->start(cmd, args);
    m_proc->setReadChannel(QProcess::StandardError);
    if (!m_proc->waitForStarted())
        throw Exception(gpg_error(GPG_ERR_EIO), i18n("Could not start %1 process: %2", cmd, m_proc->errorString()));
}

QString ProcessStdInOutput::label() const
{
    return QFileInfo(m_file).fileName();
}

QString ProcessStdInOutput::doErrorString() const
{
    kleo_assert(m_proc);
    if (m_proc->exitStatus() == QProcess::NormalExit && m_proc->exitCode() == 0) {
        return QString();
    }
    if (m_proc->error() == QProcess::UnknownError)
        return i18n("Error while running %1: %2", m_command, QString::fromLocal8Bit(m_proc->readAllStandardError().trimmed().constData()));
    else {
        return i18n("Failed to execute %1: %2", m_command, m_proc->errorString());
    }
}

#ifndef QT_NO_CLIPBOARD
std::shared_ptr<Output> Output::createFromClipboard()
{
    return std::shared_ptr<Output>(new ClipboardOutput(QClipboard::Clipboard));
}

ClipboardOutput::ClipboardOutput(QClipboard::Mode mode)
    : OutputImplBase()
    , m_mode(mode)
    , m_buffer(new QBuffer)
{
    errno = 0;
    if (!m_buffer->open(QIODevice::WriteOnly))
        throw Exception(errno ? gpg_error_from_errno(errno) : gpg_error(GPG_ERR_EIO), i18n("Could not write to clipboard"));
}

QString ClipboardOutput::label() const
{
    switch (m_mode) {
    case QClipboard::Clipboard:
        return i18n("Clipboard");
    case QClipboard::FindBuffer:
        return i18n("Find buffer");
    case QClipboard::Selection:
        return i18n("Selection");
    }
    return QString();
}

void ClipboardOutput::doFinalize()
{
    if (m_buffer->isOpen()) {
        m_buffer->close();
    }
    if (QClipboard *const cb = QApplication::clipboard()) {
        cb->setText(QString::fromUtf8(m_buffer->data()));
    } else
        throw Exception(gpg_error(GPG_ERR_EIO), i18n("Could not find clipboard"));
}
#endif // QT_NO_CLIPBOARD

Output::~Output()
{
}

OutputInput::OutputInput(const std::shared_ptr<FileOutput> &output)
    : m_output(output)
    , m_ioDevice(new QFile(output->fileName()))
{
}

std::shared_ptr<Input> Input::createFromOutput(const std::shared_ptr<Output> &output)
{
    if (auto fo = std::dynamic_pointer_cast<FileOutput>(output)) {
        auto input = std::shared_ptr<OutputInput>(new OutputInput(fo));
        fo->attachInput(input);
        return input;
    } else {
        return {};
    }
}

std::shared_ptr<Output> Output::createFromByteArray(QByteArray *data, const QString &label)
{
    auto ret = std::shared_ptr<ByteArrayOutput>(new ByteArrayOutput(data));
    ret->setLabel(label);
    return ret;
}

QString OutputInput::label() const
{
    return m_output->label();
}
