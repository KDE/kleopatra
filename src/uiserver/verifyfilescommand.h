/*
    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2007 Klarälvdalens Datakonsult AB

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#pragma once

#include <uiserver/decryptverifycommandfilesbase.h>

namespace Kleo
{

class VerifyFilesCommand : public AssuanCommandMixin<VerifyFilesCommand, DecryptVerifyCommandFilesBase>
{
public:
    // VerifyFilesCommand();
    //~VerifyFilesCommand();

private:
    DecryptVerifyOperation operation() const override
    {
        return Verify;
    }

public:
    static const char *staticName()
    {
        return "VERIFY_FILES";
    }
};

}
