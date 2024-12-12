/* -*- mode: c++; c-basic-offset:4 -*-
    decryptverifyemailcontroller.h

    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2008 Klarälvdalens Datakonsult AB

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#pragma once

#include <crypto/controller.h>

#include <utils/types.h>

#include <gpgme++/global.h>

#include <QMetaType>

#include <memory>
#include <vector>

#include <gpgme++/verificationresult.h>

namespace KMime
{
namespace Types
{
class Mailbox;
}
}

namespace Kleo
{

class Input;
class Output;

namespace Crypto
{

class DecryptVerifyEMailController : public Controller
{
    Q_OBJECT
public:
    explicit DecryptVerifyEMailController(QObject *parent = nullptr, Task::DataSource dataSource = Task::Files);
    explicit DecryptVerifyEMailController(const std::shared_ptr<const ExecutionContext> &cmd, QObject *parent = nullptr);

    ~DecryptVerifyEMailController() override;

    void setInput(const std::shared_ptr<Input> &input);
    void setInputs(const std::vector<std::shared_ptr<Input>> &inputs);

    void setSignedData(const std::shared_ptr<Input> &data);
    void setSignedData(const std::vector<std::shared_ptr<Input>> &data);

    void setOutput(const std::shared_ptr<Output> &output);
    void setOutputs(const std::vector<std::shared_ptr<Output>> &outputs);

    void setInformativeSenders(const std::vector<KMime::Types::Mailbox> &senders);

    void setWizardShown(bool shown);

    void setOperation(DecryptVerifyOperation operation);
    void setVerificationMode(VerificationMode vm);
    void setProtocol(GpgME::Protocol protocol);

    void setSessionId(unsigned int id);

    void start();

public Q_SLOTS:
    void cancel();

Q_SIGNALS:
    void verificationResult(const GpgME::VerificationResult &);

private:
    void doTaskDone(const Task *task, const std::shared_ptr<const Task::Result> &result) override;

    class Private;
    const std::unique_ptr<Private> d;
    Q_PRIVATE_SLOT(d, void slotWizardCanceled())
    Q_PRIVATE_SLOT(d, void schedule())
};

} // namespace Crypto
} // namespace Kleo

Q_DECLARE_METATYPE(GpgME::VerificationResult)
