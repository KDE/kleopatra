/* -*- mode: c++; c-basic-offset:4 -*-
    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2007 Klarälvdalens Datakonsult AB

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#pragma once

#include <crypto/controller.h>

#include <gpgme++/global.h>

#include <memory>
#include <vector>

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

class SignEMailController : public Controller
{
    Q_OBJECT
public:
    enum Mode {
        GpgOLMode,
        ClipboardMode,

        NumModes
    };

    explicit SignEMailController(Mode mode, QObject *parent = nullptr);
    explicit SignEMailController(const std::shared_ptr<ExecutionContext> &xc, Mode mode, QObject *parent = nullptr);
    ~SignEMailController() override;

    Mode mode() const;

    void setProtocol(GpgME::Protocol proto);
    GpgME::Protocol protocol() const;
    // const char * protocolAsString() const;

    void startResolveSigners();

    void setDetachedSignature(bool detached);

    void setInputAndOutput(const std::shared_ptr<Kleo::Input> &input, const std::shared_ptr<Kleo::Output> &output);
    void setInputsAndOutputs(const std::vector<std::shared_ptr<Kleo::Input>> &inputs, const std::vector<std::shared_ptr<Kleo::Output>> &outputs);

    void start();

public Q_SLOTS:
    void cancel();

Q_SIGNALS:
    void signersResolved();
    void reportMicAlg(const QString &micalg);

private:
    void doTaskDone(const Task *task, const std::shared_ptr<const Task::Result> &result) override;

    class Private;
    const std::unique_ptr<Private> d;
    Q_PRIVATE_SLOT(d, void slotWizardSignersResolved())
    Q_PRIVATE_SLOT(d, void slotWizardCanceled())
    Q_PRIVATE_SLOT(d, void schedule())
};

} // Crypto
} // Kleo
