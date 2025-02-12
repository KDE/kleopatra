/*
    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2008 Klarälvdalens Datakonsult AB

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#pragma once

#include "assuancommand.h"

#include <utils/types.h>

#include <memory>

namespace Kleo
{

class DecryptVerifyCommandEMailBase : public AssuanCommandMixin<DecryptVerifyCommandEMailBase>
{
public:
    explicit DecryptVerifyCommandEMailBase();
    ~DecryptVerifyCommandEMailBase() override;

private:
    virtual DecryptVerifyOperation operation() const = 0;
    virtual Mode mode() const
    {
        return EMail;
    }

private:
    int doStart() override;
    void doCanceled() override;

public:
    static const char *staticName()
    {
        return "";
    }

    class Private;

private:
    const std::unique_ptr<Private> d;
};

class DecryptVerifyCommand : public AssuanCommandMixin<DecryptVerifyCommand, DecryptVerifyCommandEMailBase>
{
public:
private:
    DecryptVerifyOperation operation() const override
    {
        return DecryptVerify;
    }

public:
    static const char *staticName()
    {
        return "DECRYPT_VERIFY";
    }
};
}
