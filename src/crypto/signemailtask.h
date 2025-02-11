/* -*- mode: c++; c-basic-offset:4 -*-
    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2007 Klarälvdalens Datakonsult AB

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#pragma once

#include <crypto/task.h>

#include <gpgme++/global.h>

#include <memory>
#include <vector>

namespace GpgME
{
class Key;
}

namespace Kleo
{
class Input;
class Output;
}

namespace Kleo
{
namespace Crypto
{

class SignEMailTask : public Task
{
    Q_OBJECT
public:
    explicit SignEMailTask(QObject *parent = nullptr);
    ~SignEMailTask() override;

    void setInput(const std::shared_ptr<Input> &input);
    void setOutput(const std::shared_ptr<Output> &output);
    void setSigners(const std::vector<GpgME::Key> &recipients);

    void setDetachedSignature(bool detached);
    void setClearsign(bool clear);

    GpgME::Protocol protocol() const override;

    void cancel() override;
    QString label() const override;

    QString micAlg() const;

private:
    void doStart() override;
    unsigned long long inputSize() const override;

private:
    class Private;
    const std::unique_ptr<Private> d;
    Q_PRIVATE_SLOT(d, void slotResult(const GpgME::SigningResult &))
};

}
}
