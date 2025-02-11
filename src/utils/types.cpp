/* -*- mode: c++; c-basic-offset:4 -*-
    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2008 Klarälvdalens Datakonsult AB

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include <config-kleopatra.h>

#include "utils/gui-helper.h"
#include "utils/types.h"

#include <QList>
#include <QWidget>

#ifdef Q_OS_WIN
#include <windows.h>
#endif

using namespace Kleo;

class ExecutionContextUser::Private
{
    friend class ::Kleo::ExecutionContextUser;
    ExecutionContextUser *const q;

public:
    explicit Private(const std::shared_ptr<const ExecutionContext> &ctx, ExecutionContextUser *qq)
        : q(qq)
        , executionContext(ctx)
        , idApplied()
    {
    }

private:
    void applyWindowID(QWidget *w);

private:
    std::weak_ptr<const ExecutionContext> executionContext;
    QList<QWidget *> idApplied;
};

void ExecutionContextUser::applyWindowID(QWidget *wid)
{
    if (d->idApplied.contains(wid)) {
        return;
    }
    if (const std::shared_ptr<const ExecutionContext> ctx = d->executionContext.lock()) {
        ctx->applyWindowID(wid);
        d->idApplied.append(wid);
    }
}

ExecutionContextUser::ExecutionContextUser()
    : d(new Private(std::shared_ptr<const ExecutionContext>(), this))
{
}

ExecutionContextUser::ExecutionContextUser(const std::shared_ptr<const ExecutionContext> &ctx)
    : d(new Private(ctx, this))
{
}

ExecutionContextUser::~ExecutionContextUser()
{
}

void ExecutionContextUser::setExecutionContext(const std::shared_ptr<const ExecutionContext> &ctx)
{
    d->executionContext = ctx;
    d->idApplied.clear();
}

std::shared_ptr<const ExecutionContext> ExecutionContextUser::executionContext() const
{
    return d->executionContext.lock();
}

void ExecutionContextUser::bringToForeground(QWidget *wid, bool stayOnTop)
{
    applyWindowID(wid);
    wid->show();
    aggressive_raise(wid, stayOnTop);
}
