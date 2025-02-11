/* -*- mode: c++; c-basic-offset:4 -*-
    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2007 Klarälvdalens Datakonsult AB

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#pragma once

#include <uiserver/decryptverifycommandfilesbase.h>

namespace Kleo
{

class DecryptVerifyFilesCommand : public AssuanCommandMixin<DecryptVerifyFilesCommand, DecryptVerifyCommandFilesBase>
{
public:
    // DecryptVerifyFilesCommand();
    //~DecryptVerifyFilesCommand();

private:
    DecryptVerifyOperation operation() const override
    {
        return DecryptVerify;
    }

public:
    static const char *staticName()
    {
        return "DECRYPT_VERIFY_FILES";
    }
};

}
