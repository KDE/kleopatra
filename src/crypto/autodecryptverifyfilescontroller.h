/*
    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2008 Klarälvdalens Datakonsult AB

    SPDX-FileCopyrightText: 2016 Bundesamt für Sicherheit in der Informationstechnik
    SPDX-FileContributor: Intevation GmbH

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#pragma once

#include "crypto/decryptverifyfilescontroller.h"

#include <utils/types.h>

#include <memory>
#include <vector>

namespace Kleo
{
namespace Crypto
{

class AutoDecryptVerifyFilesController : public DecryptVerifyFilesController
{
    Q_OBJECT
public:
    explicit AutoDecryptVerifyFilesController(QObject *parent = nullptr);
    explicit AutoDecryptVerifyFilesController(const std::shared_ptr<const ExecutionContext> &ctx, QObject *parent = nullptr);

    ~AutoDecryptVerifyFilesController() override;

    void setFiles(const QStringList &files) override;
    void setOperation(DecryptVerifyOperation op) override;
    DecryptVerifyOperation operation() const override;
    void start() override;

public Q_SLOTS:
    void cancel() override;

private:
    void doTaskDone(const Task *task, const std::shared_ptr<const Task::Result> &) override;

private:
    class Private;
    const std::unique_ptr<Private> d;
    Q_PRIVATE_SLOT(d, void schedule())
};

}
}
