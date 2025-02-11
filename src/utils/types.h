/* -*- mode: c++; c-basic-offset:4 -*-
    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2007 Klarälvdalens Datakonsult AB

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#pragma once

#include <memory>

class QWidget;

namespace Kleo
{
enum DecryptVerifyOperation {
    Decrypt,
    Verify,
    DecryptVerify,
    // VerifyOpaque,
    // VerifyDetached,
};

enum VerificationMode {
    Opaque,
    Detached,
};

enum Policy {
    NoPolicy,
    Allow,
    Force,
    Deny,
};

class ExecutionContext
{
public:
    virtual ~ExecutionContext()
    {
    }
    virtual void applyWindowID(QWidget *widget) const = 0;
};

class ExecutionContextUser
{
public:
    ExecutionContextUser();
    explicit ExecutionContextUser(const std::shared_ptr<const ExecutionContext> &ec);
    virtual ~ExecutionContextUser();

    void setExecutionContext(const std::shared_ptr<const ExecutionContext> &ec);
    std::shared_ptr<const ExecutionContext> executionContext() const;

protected:
    void bringToForeground(QWidget *wid, bool stayOnTop = false);
    void applyWindowID(QWidget *wid);

private:
    class Private;
    const std::unique_ptr<Private> d;
};

}
