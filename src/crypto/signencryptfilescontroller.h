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

namespace Kleo
{
namespace Crypto
{

class SignEncryptFilesController : public Controller
{
    Q_OBJECT
public:
    explicit SignEncryptFilesController(QObject *parent = nullptr);
    explicit SignEncryptFilesController(const std::shared_ptr<const ExecutionContext> &ctx, QObject *parent = nullptr);
    ~SignEncryptFilesController() override;

    void setProtocol(GpgME::Protocol proto);
    GpgME::Protocol protocol() const;
    // const char * protocolAsString() const;

    enum Operation {
        SignDisallowed = 0,
        SignAllowed = 1,
        SignSelected = 2,

        SignMask = SignAllowed | SignSelected,

        EncryptDisallowed = 0,
        EncryptAllowed = 4,
        EncryptSelected = 8,

        EncryptMask = EncryptAllowed | EncryptSelected,

        ArchiveDisallowed = 0,
        ArchiveAllowed = 16,
        ArchiveForced = 32,

        ArchiveMask = ArchiveAllowed | ArchiveForced
    };
    void setOperationMode(unsigned int mode);
    unsigned int operationMode() const;

    void setFiles(const QStringList &files);

    void start();

public Q_SLOTS:
    void cancel();

private:
    void doTaskDone(const Task *task, const std::shared_ptr<const Task::Result> &) override;

    class Private;
    const std::unique_ptr<Private> d;
    Q_PRIVATE_SLOT(d, void slotWizardOperationPrepared())
    Q_PRIVATE_SLOT(d, void slotWizardCanceled())
    Q_PRIVATE_SLOT(d, void schedule())
};

}
}
