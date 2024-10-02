/* -*- mode: c++; c-basic-offset:4 -*-
    crypto/signencrypttask.h

    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2007 Klarälvdalens Datakonsult AB

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#pragma once

#include <crypto/task.h>

#include <gpgme++/global.h>

#include <memory>
#include <vector>

class QString;

namespace GpgME
{
class Key;
}

namespace Kleo
{
class OverwritePolicy;
class Input;
class Output;
}

namespace Kleo
{
namespace Crypto
{

class SignEncryptTask : public Task
{
    Q_OBJECT
public:
    explicit SignEncryptTask(QObject *parent = nullptr);
    ~SignEncryptTask() override;

    void setInputFileName(const QString &fileName);
    void setInputFileNames(const QStringList &fileNames);
    void setInput(const std::shared_ptr<Input> &input);
    void setOutput(const std::shared_ptr<Output> &output);
    void setOutputFileName(const QString &fileName);
    QString outputFileName() const;
    void setSigners(const std::vector<GpgME::Key> &signers);
    void setRecipients(const std::vector<GpgME::Key> &recipients);

    void setSign(bool sign);
    void setEncrypt(bool encrypt);
    void setDetachedSignature(bool detached);
    bool detachedSignatureEnabled() const;
    void setEncryptSymmetric(bool symmetric);
    void setClearsign(bool clearsign);
    void setCreateArchive(bool archive);

    void setOverwritePolicy(const std::shared_ptr<OverwritePolicy> &policy);
    GpgME::Protocol protocol() const override;

    void cancel() override;
    QString label() const override;
    QString tag() const override;

    void setIsNotepad(bool isNotepad);

private:
    void doStart() override;
    unsigned long long inputSize() const override;

private:
    class Private;
    const std::unique_ptr<Private> d;
    Q_PRIVATE_SLOT(d, void slotResult(const GpgME::SigningResult &))
    Q_PRIVATE_SLOT(d, void slotResult(const GpgME::SigningResult &, const GpgME::EncryptionResult &))
    Q_PRIVATE_SLOT(d, void slotResult(const GpgME::EncryptionResult &))
};

}
}
