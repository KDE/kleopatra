/* -*- mode: c++; c-basic-offset:4 -*-
    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2008 Klarälvdalens Datakonsult AB

    SPDX-FileCopyrightText: 2016 Bundesamt für Sicherheit in der Informationstechnik
    SPDX-FileContributor: Intevation GmbH

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include <config-kleopatra.h>

#include "taskcollection.h"

#include "kleopatra_debug.h"
#include "task.h"

#include <Libkleo/GnuPG>

#include <algorithm>
#include <map>

#include <cmath>

#include <KLocalizedString>

using namespace Kleo;
using namespace Kleo::Crypto;

class TaskCollection::Private
{
    TaskCollection *const q;

public:
    explicit Private(TaskCollection *qq);

    void taskProgress();
    void taskResult(const std::shared_ptr<const Task::Result> &);
    void taskStarted();
    void calculateAndEmitProgress();

    std::map<int, std::shared_ptr<Task>> m_tasks;
    mutable quint64 m_totalProgress;
    mutable quint64 m_progress;
    unsigned int m_nCompleted;
    unsigned int m_nErrors;
    bool m_errorOccurred;
    bool m_doneEmitted;
};

TaskCollection::Private::Private(TaskCollection *qq)
    : q(qq)
    , m_totalProgress(0)
    , m_progress(0)
    , m_nCompleted(0)
    , m_nErrors(0)
    , m_errorOccurred(false)
    , m_doneEmitted(false)
{
}

int TaskCollection::numberOfCompletedTasks() const
{
    return d->m_nCompleted;
}

size_t TaskCollection::size() const
{
    return d->m_tasks.size();
}

bool TaskCollection::allTasksCompleted() const
{
    Q_ASSERT(d->m_nCompleted <= d->m_tasks.size());
    return d->m_nCompleted == d->m_tasks.size();
}

void TaskCollection::Private::taskProgress()
{
    calculateAndEmitProgress();
}

void TaskCollection::Private::taskResult(const std::shared_ptr<const Task::Result> &result)
{
    Q_ASSERT(result);
    ++m_nCompleted;

    if (result->hasError()) {
        m_errorOccurred = true;
        ++m_nErrors;
    }
    calculateAndEmitProgress();
    Q_EMIT q->result(result);
    if (!m_doneEmitted && q->allTasksCompleted()) {
        Q_EMIT q->done();
        m_doneEmitted = true;
    }
}

void TaskCollection::Private::taskStarted()
{
    const Task *const task = qobject_cast<Task *>(q->sender());
    Q_ASSERT(task);
    Q_ASSERT(m_tasks.find(task->id()) != m_tasks.end());
    Q_EMIT q->started(m_tasks[task->id()]);
    calculateAndEmitProgress(); // start Knight-Rider-Mode right away (gpgsm doesn't report _any_ progress).
    if (m_doneEmitted) {
        // We are not done anymore, one task restarted.
        m_nCompleted--;
        m_nErrors--;
        m_doneEmitted = false;
    }
}

void TaskCollection::Private::calculateAndEmitProgress()
{
    quint64 total = 0;
    quint64 processed = 0;

    static bool haveWorkingProgress = engineIsVersion(2, 1, 15);
    if (!haveWorkingProgress) {
        // GnuPG before 2.1.15 would overflow on progress values > max int.
        // and did not emit a total for our Qt data types.
        // As we can't know if it overflowed or what the total is we just knight
        // rider in that case
        if (m_doneEmitted) {
            Q_EMIT q->progress(1, 1);
        } else {
            Q_EMIT q->progress(0, 0);
        }
        return;
    }

    bool unknowable = false;
    for (auto it = m_tasks.begin(), end = m_tasks.end(); it != end; ++it) {
        // Sum up progress and totals
        const std::shared_ptr<Task> &i = it->second;
        Q_ASSERT(i);
        if (!i->totalProgress()) {
            // There still might be jobs for which we don't know the progress.
            qCDebug(KLEOPATRA_LOG) << "Task: " << i->label() << " has no total progress set. ";
            unknowable = true;
            break;
        }
        processed += i->currentProgress();
        total += i->totalProgress();
    }

    m_totalProgress = total;
    m_progress = processed;
    if (!unknowable && processed && total >= processed) {
        // Scale down to avoid range issues.
        int scaled = 1000 * (m_progress / static_cast<double>(m_totalProgress));
        qCDebug(KLEOPATRA_LOG) << "Collection Progress: " << scaled << " total: " << 1000;
        if (total == processed) {
            // This can happen when an output is finalizing, e.g. extracting an
            // archive.
            Q_EMIT q->progress(0, 0);
        } else {
            Q_EMIT q->progress(scaled, 1000);
        }
    } else {
        if (total < processed) {
            qCDebug(KLEOPATRA_LOG) << "Total progress is smaller then current progress.";
        }
        // Knight rider.
        Q_EMIT q->progress(0, 0);
    }
}

TaskCollection::TaskCollection(QObject *parent)
    : QObject(parent)
    , d(new Private(this))
{
}

TaskCollection::~TaskCollection()
{
}

bool TaskCollection::isEmpty() const
{
    return d->m_tasks.empty();
}

bool TaskCollection::errorOccurred() const
{
    return d->m_errorOccurred;
}

bool TaskCollection::allTasksHaveErrors() const
{
    return d->m_nErrors == d->m_nCompleted;
}

std::shared_ptr<Task> TaskCollection::taskById(int id) const
{
    const auto it = d->m_tasks.find(id);
    return it != d->m_tasks.end() ? it->second : std::shared_ptr<Task>();
}

std::vector<std::shared_ptr<Task>> TaskCollection::tasks() const
{
    std::vector<std::shared_ptr<Task>> res;
    res.reserve(d->m_tasks.size());
    for (auto it = d->m_tasks.begin(), end = d->m_tasks.end(); it != end; ++it) {
        res.push_back(it->second);
    }
    return res;
}

void TaskCollection::setTasks(const std::vector<std::shared_ptr<Task>> &tasks)
{
    for (const std::shared_ptr<Task> &i : tasks) {
        Q_ASSERT(i);
        d->m_tasks[i->id()] = i;
        connect(i.get(), &Task::progress, this, [this]() {
            d->taskProgress();
        });
        connect(i.get(),
                SIGNAL(result(std::shared_ptr<const Kleo::Crypto::Task::Result>)),
                this,
                SLOT(taskResult(std::shared_ptr<const Kleo::Crypto::Task::Result>)));
        connect(i.get(), SIGNAL(started()), this, SLOT(taskStarted()));
    }
}

#include "moc_taskcollection.cpp"
