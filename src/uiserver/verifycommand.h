/*
    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2007 Klarälvdalens Datakonsult AB

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#pragma once

#include "assuancommand.h"

namespace Kleo
{
class VerifyCommand : public AssuanCommandMixin<VerifyCommand, DecryptVerifyCommandEMailBase>
{
public:
    // VerifyCommand();
    //~VerifyCommand();

private:
    DecryptVerifyOperation operation() const override
    {
        return Verify;
    }
    Mode mode() const override
    {
        return EMail;
    }

public:
    static const char *staticName()
    {
        return "VERIFY";
    }
};

}
