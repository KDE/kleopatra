/* -*- mode: c++; c-basic-offset:4 -*-
    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2009 Klarälvdalens Datakonsult AB

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include <config-kleopatra.h>

#include "sessiondata.h"

#include "kleopatra_debug.h"

#include <QMutex>

using namespace Kleo;

static const int GARBAGE_COLLECTION_INTERVAL = 60000; // 1min

static QMutex mutex;

SessionData::SessionData()
    : mementos()
    , ref(0)
    , ripe(false)
{
}

// static
std::shared_ptr<SessionDataHandler> SessionDataHandler::instance()
{
    mutex.lock();
    static SessionDataHandler handler;
    return std::shared_ptr<SessionDataHandler>(&handler, [](SessionDataHandler *) {
        mutex.unlock();
    });
}

SessionDataHandler::SessionDataHandler()
    : QObject()
    , data()
    , timer()
{
    timer.setInterval(GARBAGE_COLLECTION_INTERVAL);
    timer.setSingleShot(false);
}

void SessionDataHandler::enterSession(unsigned int id)
{
    qCDebug(KLEOPATRA_LOG) << id;
    const std::shared_ptr<SessionData> sd = sessionDataInternal(id);
    Q_ASSERT(sd);
    ++sd->ref;
    sd->ripe = false;
}

void SessionDataHandler::exitSession(unsigned int id)
{
    qCDebug(KLEOPATRA_LOG) << id;
    const std::shared_ptr<SessionData> sd = sessionDataInternal(id);
    Q_ASSERT(sd);
    if (--sd->ref <= 0) {
        sd->ref = 0;
        sd->ripe = false;
        if (!timer.isActive()) {
            QMetaObject::invokeMethod(&timer, "start", Qt::QueuedConnection);
        }
    }
}

std::shared_ptr<SessionData> SessionDataHandler::sessionDataInternal(unsigned int id) const
{
    auto it = data.lower_bound(id);
    if (it == data.end() || it->first != id) {
        const std::shared_ptr<SessionData> sd(new SessionData);
        it = data.insert(it, std::make_pair(id, sd));
    }
    return it->second;
}

std::shared_ptr<SessionData> SessionDataHandler::sessionData(unsigned int id) const
{
    return sessionDataInternal(id);
}

void SessionDataHandler::clear()
{
    data.clear();
}

void SessionDataHandler::slotCollectGarbage()
{
    const QMutexLocker locker(&mutex);
    unsigned int alive = 0;
    auto it = data.begin(), end = data.end();
    while (it != end)
        if (it->second->ripe) {
            data.erase(it++);
        } else if (!it->second->ref) {
            it->second->ripe = true;
            ++it;
        } else {
            ++alive;
            ++it;
        }
    if (alive == data.size()) {
        QMetaObject::invokeMethod(&timer, "stop", Qt::QueuedConnection);
    }
}

#include "moc_sessiondata.cpp"
