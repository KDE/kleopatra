/* -*- mode: c++; c-basic-offset:4 -*-
    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2008 Klarälvdalens Datakonsult AB

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#pragma once

#include <QObject>

#include <crypto/task.h>

#include <utils/types.h>

#include <memory>

namespace Kleo
{
namespace Crypto
{

class Controller : public QObject, protected ExecutionContextUser
{
    Q_OBJECT
public:
    explicit Controller(QObject *parent = nullptr);
    explicit Controller(const std::shared_ptr<const ExecutionContext> &cmd, QObject *parent = nullptr);
    ~Controller() override;

    using ExecutionContextUser::setExecutionContext;

Q_SIGNALS:
    void progress(int current, int total, const QString &what);

protected:
    void emitDoneOrError();
    void setLastError(int err, const QString &details);
    void connectTask(const std::shared_ptr<Task> &task);

    virtual void doTaskDone(const Task *task, const std::shared_ptr<const Task::Result> &result);

protected Q_SLOTS:
    void taskDone(const std::shared_ptr<const Kleo::Crypto::Task::Result> &);

Q_SIGNALS:
    /**
     * Private signal, you can connect to it, but derived classes cannot emit it.
     */
    void error(int err,
               const QString &details
#ifndef DOXYGEN_SHOULD_SKIP_THIS
               ,
               QPrivateSignal
#endif
    );

    /**
     * Private signal, you can connect to it, but derived classes cannot emit it.
     */
    void done(
#ifndef DOXYGEN_SHOULD_SKIP_THIS
        QPrivateSignal
#endif
    );

private:
    class Private;
    const std::unique_ptr<Private> d;
};

}
}
