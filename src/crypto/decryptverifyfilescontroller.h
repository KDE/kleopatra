/*
    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2008 Klarälvdalens Datakonsult AB

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#pragma once

#include "crypto/controller.h"

#include "utils/archivedefinition.h"
#include "utils/types.h"

#include <QMetaType>

#include <memory>
#include <vector>

#include <gpgme++/verificationresult.h>

namespace Kleo
{
namespace Crypto
{

class DecryptVerifyFilesController : public Controller
{
    Q_OBJECT
public:
    explicit DecryptVerifyFilesController(QObject *parent = nullptr);
    explicit DecryptVerifyFilesController(const std::shared_ptr<const ExecutionContext> &ctx, QObject *parent = nullptr);

    ~DecryptVerifyFilesController() override;

    virtual void setFiles(const QStringList &files);
    virtual void setOperation(DecryptVerifyOperation op);
    virtual DecryptVerifyOperation operation() const;
    virtual void start();

public Q_SLOTS:
    virtual void cancel();

protected:
    std::shared_ptr<ArchiveDefinition>
    pick_archive_definition(GpgME::Protocol proto, const std::vector<std::shared_ptr<ArchiveDefinition>> &ads, const QString &filename);

Q_SIGNALS:
    void verificationResult(const GpgME::VerificationResult &);

private:
    void doTaskDone(const Task *task, const std::shared_ptr<const Task::Result> &) override;

private:
    class Private;
    std::shared_ptr<Private> d;
    Q_PRIVATE_SLOT(d, void slotWizardOperationPrepared())
    Q_PRIVATE_SLOT(d, void slotWizardCanceled())
    Q_PRIVATE_SLOT(d, void schedule())
};

}
}

Q_DECLARE_METATYPE(GpgME::VerificationResult)
