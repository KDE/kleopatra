/* -*- mode: c++; c-basic-offset:4 -*-
    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2008 Klarälvdalens Datakonsult AB

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include <config-kleopatra.h>

#include "controller.h"

using namespace Kleo;
using namespace Kleo::Crypto;

class Controller::Private
{
    friend class ::Kleo::Crypto::Controller;
    Controller *const q;

public:
    explicit Private(Controller *qq)
        : q(qq)
    {
    }

private:
    int lastError = 0;
    QString lastErrorString;
};

Controller::Controller(QObject *parent)
    : QObject(parent)
    , ExecutionContextUser()
    , d(new Private(this))
{
}

Controller::Controller(const std::shared_ptr<const ExecutionContext> &ctx, QObject *parent)
    : QObject(parent)
    , ExecutionContextUser(ctx)
    , d(new Private(this))
{
}

Controller::~Controller()
{
}

void Controller::taskDone(const std::shared_ptr<const Task::Result> &result)
{
    const Task *task = qobject_cast<const Task *>(sender());
    Q_ASSERT(task);
    doTaskDone(task, result);
}

void Controller::doTaskDone(const Task *, const std::shared_ptr<const Task::Result> &)
{
}

void Controller::connectTask(const std::shared_ptr<Task> &task)
{
    Q_ASSERT(task);
    connect(task.get(), &Task::result, this, &Controller::taskDone);
}

void Controller::setLastError(int err, const QString &msg)
{
    d->lastError = err;
    d->lastErrorString = msg;
}

void Controller::emitDoneOrError()
{
    if (d->lastError) {
        Q_EMIT error(d->lastError, d->lastErrorString, QPrivateSignal{});
        d->lastError = 0;
        d->lastErrorString = QString();
    } else {
        Q_EMIT done(QPrivateSignal{});
    }
}

#include "moc_controller.cpp"
