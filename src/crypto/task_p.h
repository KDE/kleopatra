/*
    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2007 Klarälvdalens Datakonsult AB

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#pragma once

#include <crypto/task.h>

#include <QString>
#include <QTimer>

namespace Kleo
{
namespace Crypto
{

class SimpleTask : public Task
{
    Q_OBJECT
public:
    explicit SimpleTask(const QString &label)
        : m_result()
        , m_label(label)
    {
    }

    void setResult(const std::shared_ptr<const Task::Result> &res)
    {
        m_result = res;
    }
    GpgME::Protocol protocol() const override
    {
        return GpgME::UnknownProtocol;
    }
    QString label() const override
    {
        return m_label;
    }
    void cancel() override
    {
    }

private:
    void doStart() override
    {
        QTimer::singleShot(0, this, &SimpleTask::slotEmitResult);
    }
    unsigned long long inputSize() const override
    {
        return 0;
    }

private Q_SLOTS:
    void slotEmitResult()
    {
        emitResult(m_result);
    }

private:
    std::shared_ptr<const Task::Result> m_result;
    QString m_label;
};
}
}
