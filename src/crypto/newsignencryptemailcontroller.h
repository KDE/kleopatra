/*
    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2007 Klarälvdalens Datakonsult AB

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#pragma once

#include <crypto/controller.h>

#include <gpgme++/global.h>

#include <memory>
#include <utility>
#include <vector>

namespace KMime
{
namespace Types
{
class Mailbox;
}
}

namespace GpgME
{
}

namespace Kleo
{

class Input;
class Output;

namespace Crypto
{

class NewSignEncryptEMailController : public Controller
{
    Q_OBJECT
public:
    explicit NewSignEncryptEMailController(QObject *parent = nullptr);
    explicit NewSignEncryptEMailController(const std::shared_ptr<ExecutionContext> &xc, QObject *parent = nullptr);
    ~NewSignEncryptEMailController() override;

    static const char *mementoName()
    {
        return "NewSignEncryptEMailController";
    }

    // 1st stage inputs

    void setSubject(const QString &subject);
    void setProtocol(GpgME::Protocol proto);
    const char *protocolAsString() const;
    GpgME::Protocol protocol() const;

    void setSigning(bool sign);
    bool isSigning() const;

    void setEncrypting(bool encrypt);
    bool isEncrypting() const;

    void startResolveCertificates(const std::vector<KMime::Types::Mailbox> &recipients, const std::vector<KMime::Types::Mailbox> &senders);

    bool isResolvingInProgress() const;
    bool areCertificatesResolved() const;

    // 2nd stage inputs

    void setDetachedSignature(bool detached);

    void startSigning(const std::vector<std::shared_ptr<Kleo::Input>> &inputs, const std::vector<std::shared_ptr<Kleo::Output>> &outputs);

    void startEncryption(const std::vector<std::shared_ptr<Kleo::Input>> &inputs, const std::vector<std::shared_ptr<Kleo::Output>> &outputs);

public Q_SLOTS:
    void cancel();

Q_SIGNALS:
    void certificatesResolved();
    void reportMicAlg(const QString &micAlg);

private:
    void doTaskDone(const Task *task, const std::shared_ptr<const Kleo::Crypto::Task::Result> &) override;

    class Private;
    const std::unique_ptr<Private> d;
    Q_PRIVATE_SLOT(d, void slotDialogAccepted())
    Q_PRIVATE_SLOT(d, void slotDialogRejected())
    Q_PRIVATE_SLOT(d, void schedule())
};

} // Crypto
} // Kleo
