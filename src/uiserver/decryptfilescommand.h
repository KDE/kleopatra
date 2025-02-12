/*
    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2007 Klarälvdalens Datakonsult AB

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#pragma once

#include <uiserver/decryptverifycommandfilesbase.h>

namespace Kleo
{

class DecryptFilesCommand : public AssuanCommandMixin<DecryptFilesCommand, DecryptVerifyCommandFilesBase>
{
public:
    // DecryptFilesCommand();
    //~DecryptFilesCommand();

private:
    DecryptVerifyOperation operation() const override
    {
        return Decrypt;
    }

public:
    static const char *staticName()
    {
        return "DECRYPT_FILES";
    }
};

}
