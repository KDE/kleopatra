/*
    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2020 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include "deviceinfowatcher.h"
#include "deviceinfowatcher_p.h"

#include <KConfigGroup>
#include <KSharedConfig>

#include <QGpgME/Debug>

#include <gpgme++/context.h>
#include <gpgme++/engineinfo.h>
#include <gpgme++/statusconsumerassuantransaction.h>

#include "kleopatra_debug.h"

using namespace Kleo;
using namespace GpgME;
using namespace std::chrono_literals;

static const auto initialRetryDelay = 125ms;
static const auto maxRetryDelay = 1000ms;
static const auto maxConnectionAttempts = 10;

DeviceInfoWatcher::Worker::Worker()
    : mRetryDelay{initialRetryDelay}
{
}

DeviceInfoWatcher::Worker::~Worker()
{
    if (mContext) {
        mContext->cancelPendingOperationImmediately();
    }
}

void DeviceInfoWatcher::Worker::start()
{
    if (!mContext) {
        Error err;
        mContext = Context::createForEngine(AssuanEngine, &err);
        if (err) {
            qCWarning(KLEOPATRA_LOG) << "DeviceInfoWatcher::Worker::start: Creating context failed:" << err;
            return;
        }
    }

    static const char *command = "SCD DEVINFO --watch";
    std::unique_ptr<AssuanTransaction> t(new StatusConsumerAssuanTransaction(this));
    const Error err = mContext->startAssuanTransaction(command, std::move(t));
    if (!err) {
        qCDebug(KLEOPATRA_LOG) << "DeviceInfoWatcher::Worker::start: Assuan transaction for" << command << "started";
        mRetryDelay = initialRetryDelay;
        mFailedConnectionAttempts = 0;
        QMetaObject::invokeMethod(this, "poll", Qt::QueuedConnection);
        return;
    } else if (err.code() == GPG_ERR_ASS_CONNECT_FAILED) {
        mFailedConnectionAttempts++;
        if (mFailedConnectionAttempts == 1) {
            Q_EMIT startOfGpgAgentRequested();
        }
        if (mFailedConnectionAttempts < maxConnectionAttempts) {
            qCInfo(KLEOPATRA_LOG) << "DeviceInfoWatcher::Worker::start: Connecting to the agent failed. Retrying in" << mRetryDelay.count() << "ms";
            QThread::msleep(mRetryDelay.count());
            mRetryDelay = std::min(mRetryDelay * 2, maxRetryDelay);
            QMetaObject::invokeMethod(this, "start", Qt::QueuedConnection);
            return;
        }
        qCWarning(KLEOPATRA_LOG) << "DeviceInfoWatcher::Worker::start: Connecting to the agent failed too often. Giving up.";
    } else if (err.code() == GPG_ERR_EPIPE) {
        qCDebug(KLEOPATRA_LOG)
            << "DeviceInfoWatcher::Worker::start: Assuan transaction failed with broken pipe. The agent seems to have died. Resetting context.";
        mContext.reset();
        QMetaObject::invokeMethod(this, "start", Qt::QueuedConnection);
    } else {
        qCWarning(KLEOPATRA_LOG) << "DeviceInfoWatcher::Worker::start: Starting Assuan transaction for" << command << "failed:" << err;
    }
}

void DeviceInfoWatcher::Worker::poll()
{
    const bool finished = mContext->poll();
    if (finished) {
        qCDebug(KLEOPATRA_LOG) << "DeviceInfoWatcher::Worker::poll: context finished with" << mContext->lastError();
        QThread::msleep(1000);
        QMetaObject::invokeMethod(this, "start", Qt::QueuedConnection);
    } else {
        QMetaObject::invokeMethod(this, "poll", Qt::QueuedConnection);
    }
}

void DeviceInfoWatcher::Worker::status(const char *status, const char *details)
{
    qCDebug(KLEOPATRA_LOG) << "DeviceInfoWatcher::Worker::status:" << status << details;
    if (status && std::strcmp(status, "DEVINFO_STATUS") == 0) {
        Q_EMIT statusChanged(QByteArray(details));
    }
}

DeviceInfoWatcher::Private::Private(DeviceInfoWatcher *qq)
    : q(qq)
{
}

DeviceInfoWatcher::Private::~Private()
{
    workerThread.quit();
    workerThread.wait();
}

void DeviceInfoWatcher::Private::start()
{
    auto worker = new DeviceInfoWatcher::Worker;
    worker->moveToThread(&workerThread);
    connect(&workerThread, &QThread::started, worker, &DeviceInfoWatcher::Worker::start);
    connect(&workerThread, &QThread::finished, worker, &QObject::deleteLater);
    connect(worker, &DeviceInfoWatcher::Worker::statusChanged, q, &DeviceInfoWatcher::statusChanged);
    connect(worker, &DeviceInfoWatcher::Worker::startOfGpgAgentRequested, q, &DeviceInfoWatcher::startOfGpgAgentRequested);
    workerThread.start();
}

DeviceInfoWatcher::DeviceInfoWatcher(QObject *parent)
    : QObject(parent)
    , d(new Private(this))
{
}

DeviceInfoWatcher::~DeviceInfoWatcher()
{
    delete d;
}

// static
bool DeviceInfoWatcher::isSupported()
{
#ifdef Q_OS_WIN
    // "SCD DEVINFO --watch" seems to cause problems on Windows, e.g. https://dev.gnupg.org/T6688
    // only enable it if a "secret" config option is set
    const KConfigGroup config{KSharedConfig::openConfig(), QLatin1StringView("__Experimental__")};
    return config.readEntry("UseDeviceInfoWatcher", false);
#else
    return engineInfo(GpgEngine).engineVersion() >= "2.3.0";
#endif
}

void DeviceInfoWatcher::start()
{
    d->start();
}

#include "moc_deviceinfowatcher_p.cpp"

#include "moc_deviceinfowatcher.cpp"
