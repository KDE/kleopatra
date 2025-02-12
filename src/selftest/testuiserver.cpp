/*
    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2008 Klarälvdalens Datakonsult AB

    SPDX-License-Identifier: LGPL-2.0-or-later
*/

#include <config-kleopatra.h>

#include "testuiserver.h"

#include <KLocalizedString>
#include <QDir>
#include <QFile>
#include <QMutexLocker>
#include <QProcess>
#include <QThread>

#include <assuan.h>
#include <gpg-error.h>
#include <gpgme++/error.h>

#include <memory>
#include <string>

using namespace Kleo;

class TestUiServer::Private : public QThread
{
    Q_OBJECT
private:
    friend class ::TestUiServer;
    TestUiServer *const q;

public:
    explicit Private(TestUiServer *qq)
        : QThread()
        , q(qq)
        , mutex()
        , inputs()
        , outputs()
    {
    }
    ~Private() override
    {
    }

private:
    void init();

private:
    void run() override;

private:
    QRecursiveMutex mutex;
    struct Inputs {
        Inputs()
        {
        }
        std::map<std::string, QByteArray> inquireData;
        QByteArray command;
    } inputs;
    struct Outputs {
        Outputs()
            : serverPid(0)
        {
        }
        QString errorString;
        QByteArray data;
        qint64 serverPid;
        QString serverLocation;
    } outputs;
};

TestUiServer::TestUiServer(QObject *p)
    : QObject(p)
    , d(new Private(this))
{
    d->init();
}

TestUiServer::~TestUiServer()
{
    delete d;
    d = nullptr;
}

void TestUiServer::Private::init()
{
    connect(this, &QThread::started, q, &TestUiServer::started);
    connect(this, &QThread::finished, q, &TestUiServer::finished);
}

bool TestUiServer::error() const
{
    const QMutexLocker locker(&d->mutex);
    return !d->outputs.errorString.isEmpty();
}

QString TestUiServer::errorString() const
{
    const QMutexLocker locker(&d->mutex);
    return d->outputs.errorString;
}

qint64 TestUiServer::serverPid() const
{
    const QMutexLocker locker(&d->mutex);
    return d->outputs.serverPid;
}

void TestUiServer::start()
{
    d->start();
}

static void my_assuan_release(assuan_context_t ctx)
{
    if (ctx) {
        assuan_release(ctx);
    }
}

using AssuanContextBase = std::shared_ptr<std::remove_pointer<assuan_context_t>::type>;
namespace
{
struct AssuanClientContext : AssuanContextBase {
    AssuanClientContext()
        : AssuanContextBase()
    {
    }
    explicit AssuanClientContext(assuan_context_t ctx)
        : AssuanContextBase(ctx, &my_assuan_release)
    {
    }
    void reset(assuan_context_t ctx = nullptr)
    {
        AssuanContextBase::reset(ctx, &my_assuan_release);
    }
};
}

static gpg_error_t my_assuan_transact(const AssuanClientContext &ctx,
                                      const char *command,
                                      gpg_error_t (*data_cb)(void *, const void *, size_t) = nullptr,
                                      void *data_cb_arg = nullptr,
                                      gpg_error_t (*inquire_cb)(void *, const char *) = nullptr,
                                      void *inquire_cb_arg = nullptr,
                                      gpg_error_t (*status_cb)(void *, const char *) = nullptr,
                                      void *status_cb_arg = nullptr)
{
    return assuan_transact(ctx.get(), command, data_cb, data_cb_arg, inquire_cb, inquire_cb_arg, status_cb, status_cb_arg);
}

static QString to_error_string(int err)
{
    char buffer[1024];
    gpg_strerror_r(static_cast<gpg_error_t>(err), buffer, sizeof buffer);
    buffer[sizeof buffer - 1] = '\0';
    return QString::fromLocal8Bit(buffer);
}

static QString gnupg_home_directory()
{
    static const char *hDir = GpgME::dirInfo("homedir");
    return QFile::decodeName(hDir);
}

static QString get_default_socket_name()
{
    const QString socketPath{QString::fromUtf8(GpgME::dirInfo("uiserver-socket"))};
    if (!socketPath.isEmpty()) {
        // Note: The socket directory exists after GpgME::dirInfo() has been called.
        return socketPath;
    }
    const QString homeDir = gnupg_home_directory();
    if (homeDir.isEmpty()) {
        return QString();
    }
    return QDir(homeDir).absoluteFilePath(QStringLiteral("S.uiserver"));
}

static QString uiserver_executable()
{
    return QStringLiteral("kleopatra");
}

static QString start_uiserver()
{
    // Warning: Don't assume that the program needs to be in PATH. On Windows, it will also be found next to the calling process.
    if (!QProcess::startDetached(uiserver_executable(), QStringList() << QStringLiteral("--daemon"))) {
        return i18n("Failed to start uiserver %1", uiserver_executable());
    } else {
        return QString();
    }
}

static gpg_error_t getinfo_pid_cb(void *opaque, const void *buffer, size_t length)
{
    qint64 &pid = *static_cast<qint64 *>(opaque);
    pid = QByteArray(static_cast<const char *>(buffer), length).toLongLong();
    return 0;
}

static gpg_error_t command_data_cb(void *opaque, const void *buffer, size_t length)
{
    QByteArray &ba = *static_cast<QByteArray *>(opaque);
    ba.append(QByteArray(static_cast<const char *>(buffer), length));
    return 0;
}

namespace
{
struct inquire_data {
    const std::map<std::string, QByteArray> *map;
    const AssuanClientContext *ctx;
};
}

static gpg_error_t command_inquire_cb(void *opaque, const char *what)
{
    if (!opaque) {
        return 0;
    }
    const inquire_data &id = *static_cast<const inquire_data *>(opaque);
    const auto it = id.map->find(what);
    if (it != id.map->end()) {
        const QByteArray &v = it->second;
        assuan_send_data(id.ctx->get(), v.data(), v.size());
    }
    return 0;
}

void TestUiServer::Private::run()
{
    // Take a snapshot of the input data, and clear the output data:
    Inputs in;
    Outputs out;
    {
        const QMutexLocker locker(&mutex);
        in = inputs;
        outputs = out;
    }

    AssuanClientContext ctx;
    gpg_error_t err = 0;

    inquire_data id = {&in.inquireData, &ctx};

    const QString socketName = get_default_socket_name();
    if (socketName.isEmpty()) {
        out.errorString = i18n("Invalid socket name!");
        goto leave;
    }

    {
        assuan_context_t naked_ctx = nullptr;
        err = assuan_new(&naked_ctx);
        if (err) {
            out.errorString = i18n("Could not allocate resources to connect to Kleopatra UI server at %1: %2", socketName, to_error_string(err));
            goto leave;
        }

        ctx.reset(naked_ctx);
    }

    err = assuan_socket_connect(ctx.get(), socketName.toUtf8().constData(), -1, 0);
    if (err) {
        qDebug("UI server not running, starting it");

        const QString errorString = start_uiserver();
        if (!errorString.isEmpty()) {
            out.errorString = errorString;
            goto leave;
        }

        // give it a bit of time to start up and try a couple of times
        for (int i = 0; err && i < 20; ++i) {
            msleep(500);
            err = assuan_socket_connect(ctx.get(), socketName.toUtf8().constData(), -1, 0);
        }
    }

    if (err) {
        out.errorString = i18n("Could not connect to Kleopatra UI server at %1: %2", socketName, to_error_string(err));
        goto leave;
    }

    out.serverPid = -1;
    err = my_assuan_transact(ctx, "GETINFO pid", &getinfo_pid_cb, &out.serverPid);
    if (err || out.serverPid <= 0) {
        out.errorString = i18n("Could not get the process-id of the Kleopatra UI server at %1: %2", socketName, to_error_string(err));
        goto leave;
    }

    if (in.command.isEmpty()) {
        goto leave;
    }

    err = my_assuan_transact(ctx, in.command.constData(), &command_data_cb, &out.data, &command_inquire_cb, &id);
    if (err) {
        if (GpgME::Error{err}.isCanceled()) {
        } else {
            out.errorString = i18n("Command (%1) failed: %2", QString::fromLatin1(in.command.constData()), to_error_string(err));
        }
        goto leave;
    }

leave:
    const QMutexLocker locker(&mutex);
    // copy outputs to where Command can see them:
    outputs = out;
}

#include "moc_testuiserver.cpp"
#include "testuiserver.moc"
