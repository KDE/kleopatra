/*
    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2007 Klarälvdalens Datakonsult AB

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include <config-kleopatra.h>

#include "uiserver.h"
#include "uiserver_p.h"

#include "sessiondata.h"

#include <Libkleo/GnuPG>
#include <utils/detail_p.h>

#include <Libkleo/KleoException>
#include <Libkleo/Stl_Util>

#include "kleopatra_debug.h"
#include <KLocalizedString>

#include <gpgme++/global.h>

#include <QDir>
#include <QEventLoop>
#include <QFile>
#include <QTcpSocket>
#include <QTimer>

#include <algorithm>
#include <cerrno>

using namespace Kleo;

// static
void UiServer::setLogStream(FILE *stream)
{
    assuan_set_assuan_log_stream(stream);
}

UiServer::Private::Private(UiServer *qq)
    : QTcpServer()
    , q(qq)
    , file()
    , factories()
    , connections()
    , suggestedSocketName()
    , actualSocketName()
    , cryptoCommandsEnabled(false)
{
    assuan_set_gpg_err_source(GPG_ERR_SOURCE_DEFAULT);
    assuan_sock_init();
}

bool UiServer::Private::isStaleAssuanSocket(const QString &fileName)
{
    assuan_context_t ctx = nullptr;
    const bool error = assuan_new(&ctx) || assuan_socket_connect(ctx, QFile::encodeName(fileName).constData(), ASSUAN_INVALID_PID, 0);
    if (!error)
        assuan_release(ctx);
    return error;
}

UiServer::UiServer(const QString &socket, QObject *p)
    : QObject(p)
    , d(new Private(this))
{
    d->suggestedSocketName = d->makeFileName(socket);
}

UiServer::~UiServer()
{
    if (QFile::exists(d->actualSocketName)) {
        QFile::remove(d->actualSocketName);
    }
}

namespace
{
using Iterator = std::vector<std::shared_ptr<AssuanCommandFactory>>::iterator;
static bool empty(std::pair<Iterator, Iterator> iters)
{
    return iters.first == iters.second;
}
}

bool UiServer::registerCommandFactory(const std::shared_ptr<AssuanCommandFactory> &cf)
{
    if (cf && empty(std::equal_range(d->factories.begin(), d->factories.end(), cf, _detail::ByName<std::less>()))) {
        d->factories.push_back(cf);
        std::inplace_merge(d->factories.begin(), d->factories.end() - 1, d->factories.end(), _detail::ByName<std::less>());
        return true;
    } else {
        if (!cf) {
            qCWarning(KLEOPATRA_LOG) << "NULL factory";
        } else {
            qCWarning(KLEOPATRA_LOG) << (void *)cf.get() << " factory already registered";
        }

        return false;
    }
}

void UiServer::start()
{
    d->makeListeningSocket();
}

void UiServer::stop()
{
    d->close();

    if (d->file.exists()) {
        d->file.remove();
    }

    if (isStopped()) {
        SessionDataHandler::instance()->clear();
        Q_EMIT stopped();
    }
}

void UiServer::enableCryptoCommands(bool on)
{
    if (on == d->cryptoCommandsEnabled) {
        return;
    }
    d->cryptoCommandsEnabled = on;
    std::for_each(d->connections.cbegin(), d->connections.cend(), [on](std::shared_ptr<AssuanServerConnection> conn) {
        conn->enableCryptoCommands(on);
    });
}

QString UiServer::socketName() const
{
    return d->actualSocketName;
}

bool UiServer::waitForStopped(unsigned int ms)
{
    if (isStopped()) {
        return true;
    }
    QEventLoop loop;
    QTimer timer;
    timer.setInterval(ms);
    timer.setSingleShot(true);
    connect(&timer, &QTimer::timeout, &loop, &QEventLoop::quit);
    connect(this, &UiServer::stopped, &loop, &QEventLoop::quit);
    loop.exec();
    return !timer.isActive();
}

bool UiServer::isStopped() const
{
    return d->connections.empty() && !d->isListening();
}

bool UiServer::isStopping() const
{
    return !d->connections.empty() && !d->isListening();
}

void UiServer::Private::slotConnectionClosed(Kleo::AssuanServerConnection *conn)
{
    qCDebug(KLEOPATRA_LOG) << "UiServer: connection " << (void *)conn << " closed";
    connections.erase(std::remove_if(connections.begin(),
                                     connections.end(),
                                     [conn](const std::shared_ptr<AssuanServerConnection> &other) {
                                         return conn == other.get();
                                     }),
                      connections.end());
    if (q->isStopped()) {
        SessionDataHandler::instance()->clear();
        Q_EMIT q->stopped();
    }
}

void UiServer::Private::incomingConnection(qintptr fd)
{
    try {
        qCDebug(KLEOPATRA_LOG) << "UiServer: client connect on fd " << fd;
        if (assuan_sock_check_nonce((assuan_fd_t)fd, &nonce)) {
            qCDebug(KLEOPATRA_LOG) << "UiServer: nonce check failed";
            assuan_sock_close((assuan_fd_t)fd);
            return;
        }
        const std::shared_ptr<AssuanServerConnection> c(new AssuanServerConnection((assuan_fd_t)fd, factories));
        connect(c.get(), &AssuanServerConnection::closed, this, &Private::slotConnectionClosed);
        connect(c.get(), &AssuanServerConnection::startKeyManagerRequested, q, &UiServer::startKeyManagerRequested, Qt::QueuedConnection);
        connect(c.get(), &AssuanServerConnection::startConfigDialogRequested, q, &UiServer::startConfigDialogRequested, Qt::QueuedConnection);
        c->enableCryptoCommands(cryptoCommandsEnabled);
        connections.push_back(c);
        qCDebug(KLEOPATRA_LOG) << "UiServer: client connection " << (void *)c.get() << " established successfully";
    } catch (const Exception &e) {
        qCDebug(KLEOPATRA_LOG) << "UiServer: client connection failed: " << e.what();
        QTcpSocket s;
        s.setSocketDescriptor(fd);
        QTextStream(&s) << "ERR " << e.error_code() << " " << e.what() << "\r\n";
        s.waitForBytesWritten();
        s.close();
    } catch (...) {
        qCDebug(KLEOPATRA_LOG) << "UiServer: client connection failed: unknown exception caught";
        // this should never happen...
        QTcpSocket s;
        s.setSocketDescriptor(fd);
        QTextStream(&s) << "ERR 63 unknown exception caught\r\n";
        s.waitForBytesWritten();
        s.close();
    }
}

QString UiServer::Private::makeFileName(const QString &socket) const
{
    if (!socket.isEmpty()) {
        return socket;
    }
    const QString socketPath{QString::fromUtf8(GpgME::dirInfo("uiserver-socket"))};
    if (!socketPath.isEmpty()) {
        // Note: The socket directory exists after GpgME::dirInfo() has been called.
        return socketPath;
    }
    // GPGME (or GnuPG) is too old to return the socket path.
    // In this case we fallback to assume that the socket directory is
    // the home directory as we did in the past.  This is not correct but
    // probably the safest fallback we can do despite that it is a
    // bug to assume the socket directory in the home directory.  See
    // https://dev.gnupg.org/T5613
    const QString gnupgHome = gnupgHomeDirectory();
    if (gnupgHome.isEmpty()) {
        throw_<std::runtime_error>(i18n("Could not determine the GnuPG home directory. Consider setting the GNUPGHOME environment variable."));
    }
    // We should not create the home directory, but this only happens for very
    // old and long unsupported versions of gnupg.
    ensureDirectoryExists(gnupgHome);
    const QDir dir(gnupgHome);
    Q_ASSERT(dir.exists());
    return dir.absoluteFilePath(QStringLiteral("S.uiserver"));
}

void UiServer::Private::ensureDirectoryExists(const QString &path) const
{
    const QFileInfo info(path);
    if (info.exists() && !info.isDir()) {
        throw_<std::runtime_error>(i18n("Cannot determine the GnuPG home directory: %1 exists but is not a directory.", path));
    }
    if (info.exists()) {
        return;
    }
    const QDir dummy; // there is no static QDir::mkpath()...
    errno = 0;
    if (!dummy.mkpath(path)) {
        throw_<std::runtime_error>(i18n("Could not create GnuPG home directory %1: %2", path, systemErrorString()));
    }
}

void UiServer::Private::makeListeningSocket()
{
    // First, create a file (we do this only for the name, gmpfh)
    const QString fileName = suggestedSocketName;

    if (QFile::exists(fileName)) {
        if (isStaleAssuanSocket(fileName)) {
            QFile::remove(fileName);
        } else {
            throw_<std::runtime_error>(i18n("Detected another running gnupg UI server listening at %1.", fileName));
        }
    }

    doMakeListeningSocket(fileName.toUtf8());

    actualSocketName = suggestedSocketName;
}

#include "moc_uiserver_p.cpp"

#include "moc_uiserver.cpp"
