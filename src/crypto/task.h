/* -*- mode: c++; c-basic-offset:4 -*-
    crypto/task.h

    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2007 Klarälvdalens Datakonsult AB

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#pragma once

#include <QObject>
#include <QString>

#include <gpgme++/global.h>

#include <QPointer>

#include <memory>

namespace Kleo
{
class AuditLogEntry;
}

namespace Kleo
{
namespace Crypto
{

class Task : public QObject
{
    Q_OBJECT
public:
    explicit Task(QObject *parent = nullptr);
    ~Task() override;

    class Result;

    void setAsciiArmor(bool armor);
    bool asciiArmor() const;

    virtual GpgME::Protocol protocol() const = 0;

    void start();

    virtual QString label() const = 0;

    virtual QString tag() const;

    int currentProgress() const;
    int totalProgress() const;

    int id() const;

    static std::shared_ptr<Task> makeErrorTask(const GpgME::Error &error, const QString &details, const QString &label);

public Q_SLOTS:
    virtual void cancel() = 0;

Q_SIGNALS:
    void progress(int processed, int total, QPrivateSignal);
    void result(const std::shared_ptr<const Kleo::Crypto::Task::Result> &, QPrivateSignal);
    void started(QPrivateSignal);

protected:
    std::shared_ptr<Result> makeErrorResult(const GpgME::Error &error, const QString &details);

    void emitResult(const std::shared_ptr<const Task::Result> &result);

protected Q_SLOTS:
    void setProgress(int processed, int total);

private Q_SLOTS:
    void emitError(const GpgME::Error &error, const QString &details);

private:
    virtual void doStart() = 0;
    virtual unsigned long long inputSize() const = 0;

private:
    class Private;
    const std::unique_ptr<Private> d;
};

class Task::Result
{
    const QString m_nonce;

public:
    class Content;

    Result();
    virtual ~Result();

    const QString &nonce() const
    {
        return m_nonce;
    }

    bool hasError() const;

    enum VisualCode {
        AllGood,
        Warning,
        Danger,
        NeutralSuccess,
        NeutralError,
    };

    enum class ContentType {
        None,
        Mime,
        Mbox,
    };

    virtual QString overview() const = 0;
    virtual QString details() const = 0;
    virtual GpgME::Error error() const = 0;
    virtual QString errorString() const = 0;
    virtual VisualCode code() const = 0;
    virtual AuditLogEntry auditLog() const = 0;
    virtual QPointer<Task> parentTask() const
    {
        return QPointer<Task>();
    }
    virtual ContentType viewableContentType() const;

    bool isNotepad() const;
    void setIsNotepad(bool isNotepad);

protected:
    static QString makeOverview(const QString &msg);

private:
    class Private;
    const std::unique_ptr<Private> d;
};
}
}
