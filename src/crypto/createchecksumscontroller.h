/* -*- mode: c++; c-basic-offset:4 -*-
    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2010 Klarälvdalens Datakonsult AB

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

class CreateChecksumsController : public Controller
{
    Q_OBJECT
public:
    explicit CreateChecksumsController(QObject *parent = nullptr);
    explicit CreateChecksumsController(const std::shared_ptr<const ExecutionContext> &ctx, QObject *parent = nullptr);
    ~CreateChecksumsController() override;

    void setAllowAddition(bool allow);
    bool allowAddition() const;

    void setFiles(const QStringList &files);

    void start();

public Q_SLOTS:
    void cancel();

private:
    class Private;
    const std::unique_ptr<Private> d;
    Q_PRIVATE_SLOT(d, void slotOperationFinished())
    Q_PRIVATE_SLOT(d, void slotProgress(int, int, QString))
};

}
}
