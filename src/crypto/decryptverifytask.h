/* -*- mode: c++; c-basic-offset:4 -*-
    decryptverifytask.h

    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2008 Klarälvdalens Datakonsult AB

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#pragma once

#include "task.h"

#include <utils/types.h>

#include <gpgme++/verificationresult.h>

#include <memory>

namespace KMime
{
namespace Types
{
class Mailbox;
}
}
namespace GpgME
{
class DecryptionResult;
class VerificationResult;
class Key;
class Signature;
}

namespace QGpgME
{
class Job;
}

namespace Kleo
{
class Input;
class Output;
class AuditLogEntry;
}

namespace Kleo
{
namespace Crypto
{

class DecryptVerifyResult;

class AbstractDecryptVerifyTask : public Task
{
    Q_OBJECT
public:
    explicit AbstractDecryptVerifyTask(QObject *parent = nullptr);
    ~AbstractDecryptVerifyTask() override;
    virtual void autodetectProtocolFromInput() = 0;

    KMime::Types::Mailbox informativeSender() const;
    void setInformativeSender(const KMime::Types::Mailbox &senders);

    virtual QString inputLabel() const = 0;
    virtual QString outputLabel() const = 0;

public Q_SLOTS:
    void cancel() override;

protected:
    std::shared_ptr<DecryptVerifyResult> fromDecryptResult(const GpgME::DecryptionResult &dr, const QByteArray &plaintext, const AuditLogEntry &auditLog);
    std::shared_ptr<DecryptVerifyResult> fromDecryptResult(const GpgME::Error &err, const QString &details, const AuditLogEntry &auditLog);
    std::shared_ptr<DecryptVerifyResult> fromDecryptVerifyResult(const GpgME::DecryptionResult &dr,
                                                                 const GpgME::VerificationResult &vr,
                                                                 const QByteArray &plaintext,
                                                                 const QString &fileName,
                                                                 const AuditLogEntry &auditLog);
    std::shared_ptr<DecryptVerifyResult> fromDecryptVerifyResult(const GpgME::Error &err, const QString &what, const AuditLogEntry &auditLog);
    std::shared_ptr<DecryptVerifyResult>
    fromVerifyOpaqueResult(const GpgME::VerificationResult &vr, const QByteArray &plaintext, const AuditLogEntry &auditLog);
    std::shared_ptr<DecryptVerifyResult> fromVerifyOpaqueResult(const GpgME::Error &err, const QString &details, const AuditLogEntry &auditLog);
    std::shared_ptr<DecryptVerifyResult> fromVerifyDetachedResult(const GpgME::VerificationResult &vr, const AuditLogEntry &auditLog);
    std::shared_ptr<DecryptVerifyResult> fromVerifyDetachedResult(const GpgME::Error &err, const QString &details, const AuditLogEntry &auditLog);

public:
    // public to allow access from the Private classes of the concrete tasks
    QGpgME::Job *job() const;
    void setJob(QGpgME::Job *job);

    void setIsNotepad(bool isNotepad);
    bool isNotepad() const;

private:
    class Private;
    const std::unique_ptr<Private> d;
};

class DecryptTask : public AbstractDecryptVerifyTask
{
    Q_OBJECT
public:
    explicit DecryptTask(QObject *parent = nullptr);
    ~DecryptTask() override;

    void setInput(const std::shared_ptr<Input> &input);
    void setOutput(const std::shared_ptr<Output> &output);

    void setProtocol(GpgME::Protocol prot);
    void autodetectProtocolFromInput() override;

    QString label() const override;

    GpgME::Protocol protocol() const override;

    QString inputLabel() const override;
    QString outputLabel() const override;

private:
    void doStart() override;
    unsigned long long inputSize() const override;

private:
    class Private;
    const std::unique_ptr<Private> d;
    Q_PRIVATE_SLOT(d, void slotResult(GpgME::DecryptionResult, QByteArray))
};

class VerifyDetachedTask : public AbstractDecryptVerifyTask
{
    Q_OBJECT
public:
    explicit VerifyDetachedTask(QObject *parent = nullptr);
    ~VerifyDetachedTask() override;

    void setInput(const std::shared_ptr<Input> &input);
    void setSignedData(const std::shared_ptr<Input> &signedData);

    void setSignatureFile(const QString &path);
    void setSignedFile(const QString &path);

    void setProtocol(GpgME::Protocol prot);
    void autodetectProtocolFromInput() override;

    QString label() const override;

    GpgME::Protocol protocol() const override;

    QString inputLabel() const override;
    QString outputLabel() const override;

private:
    void doStart() override;
    unsigned long long inputSize() const override;

private:
    class Private;
    const std::unique_ptr<Private> d;
    Q_PRIVATE_SLOT(d, void slotResult(GpgME::VerificationResult))
};

class VerifyOpaqueTask : public AbstractDecryptVerifyTask
{
    Q_OBJECT
public:
    explicit VerifyOpaqueTask(QObject *parent = nullptr);
    ~VerifyOpaqueTask() override;

    void setInput(const std::shared_ptr<Input> &input);
    void setOutput(const std::shared_ptr<Output> &output);

    void setProtocol(GpgME::Protocol prot);
    void autodetectProtocolFromInput() override;

    QString label() const override;
    GpgME::Protocol protocol() const override;

    void setExtractArchive(bool extract);
    void setInputFile(const QString &path);
    // for files
    void setOutputFile(const QString &path);
    // for archives
    void setOutputDirectory(const QString &directory);

    QString inputLabel() const override;
    QString outputLabel() const override;

private:
    void doStart() override;
    unsigned long long inputSize() const override;

private:
    class Private;
    const std::unique_ptr<Private> d;
    Q_PRIVATE_SLOT(d, void slotResult(GpgME::VerificationResult, QByteArray))
};

class DecryptVerifyTask : public AbstractDecryptVerifyTask
{
    Q_OBJECT
public:
    explicit DecryptVerifyTask(QObject *parent = nullptr);
    ~DecryptVerifyTask() override;

    void setInput(const std::shared_ptr<Input> &input);
    void setOutput(const std::shared_ptr<Output> &output);

    void setProtocol(GpgME::Protocol prot);
    void autodetectProtocolFromInput() override;

    QString label() const override;

    GpgME::Protocol protocol() const override;

    void setIgnoreMDCError(bool value);
    void setExtractArchive(bool extract);
    void setInputFile(const QString &path);
    // for files
    void setOutputFile(const QString &path);
    // for archives
    void setOutputDirectory(const QString &directory);

    QString inputLabel() const override;
    QString outputLabel() const override;

private:
    void doStart() override;
    unsigned long long inputSize() const override;

private:
    class Private;
    const std::unique_ptr<Private> d;
    Q_PRIVATE_SLOT(d, void slotResult(GpgME::DecryptionResult, GpgME::VerificationResult, QByteArray))
};

class DecryptVerifyResult : public Task::Result
{
    friend class ::Kleo::Crypto::AbstractDecryptVerifyTask;

public:
    class SenderInfo;

    QString overview() const override;
    QString details() const override;
    GpgME::Error error() const override;
    QString errorString() const override;
    VisualCode code() const override;
    AuditLogEntry auditLog() const override;
    QPointer<Task> parentTask() const override;
    Task::Result::ContentType viewableContentType() const override;

    GpgME::VerificationResult verificationResult() const;
    GpgME::DecryptionResult decryptionResult() const;
    QString fileName() const;

private:
    DecryptVerifyResult();
    DecryptVerifyResult(const DecryptVerifyResult &);
    DecryptVerifyResult &operator=(const DecryptVerifyResult &other);

    DecryptVerifyResult(DecryptVerifyOperation op,
                        const GpgME::VerificationResult &vr,
                        const GpgME::DecryptionResult &dr,
                        const QByteArray &stuff,
                        const QString &fileName,
                        const GpgME::Error &error,
                        const QString &errString,
                        const QString &inputLabel,
                        const QString &outputLabel,
                        const AuditLogEntry &auditLog,
                        Task *parentTask,
                        const KMime::Types::Mailbox &informativeSender,
                        bool isNotepad);

private:
    class Private;
    const std::unique_ptr<Private> d;
};
}
}
