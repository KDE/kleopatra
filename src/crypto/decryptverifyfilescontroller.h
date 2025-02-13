/*
    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2008 Klarälvdalens Datakonsult AB

    SPDX-FileCopyrightText: 2016 Bundesamt für Sicherheit in der Informationstechnik
    SPDX-FileContributor: Intevation GmbH

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#pragma once

#include "crypto/controller.h"

#include <utils/archivedefinition.h>
#include <utils/types.h>

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

    void setFiles(const QStringList &files);
    void setOperation(DecryptVerifyOperation op);
    DecryptVerifyOperation operation() const;
    void start();

public Q_SLOTS:
    void cancel();

Q_SIGNALS:
    void verificationResult(const GpgME::VerificationResult &);

private:
    void doTaskDone(const Task *task, const std::shared_ptr<const Task::Result> &) override;
    std::shared_ptr<ArchiveDefinition>
    pick_archive_definition(GpgME::Protocol proto, const std::vector<std::shared_ptr<ArchiveDefinition>> &ads, const QString &filename);

private:
    class Private;
    const std::unique_ptr<Private> d;
    Q_PRIVATE_SLOT(d, void schedule())
};

}
}
