/*
    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2007 Klarälvdalens Datakonsult AB

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#pragma once

#include "assuancommand.h"

#include <memory>

namespace Kleo
{

class SignEncryptFilesCommand : public Kleo::AssuanCommandMixin<SignEncryptFilesCommand>
{
public:
    SignEncryptFilesCommand();
    ~SignEncryptFilesCommand() override;

protected:
    enum Operation {
        SignDisallowed = 0,
        SignAllowed = 1,
        SignSelected = 2,

        SignMask = SignAllowed | SignSelected,

        EncryptDisallowed = 0,
        EncryptAllowed = 4,
        EncryptSelected = 8,

        EncryptMask = EncryptAllowed | EncryptSelected
    };

private:
    virtual unsigned int operation() const
    {
        return SignSelected | EncryptSelected;
    }

private:
    int doStart() override;
    void doCanceled() override;

public:
    static const char *staticName()
    {
        return "SIGN_ENCRYPT_FILES";
    }

    class Private;

private:
    const std::unique_ptr<Private> d;
};

class EncryptSignFilesCommand : public Kleo::AssuanCommandMixin<EncryptSignFilesCommand, SignEncryptFilesCommand>
{
public:
    static const char *staticName()
    {
        return "ENCRYPT_SIGN_FILES";
    }
};

class EncryptFilesCommand : public Kleo::AssuanCommandMixin<EncryptFilesCommand, SignEncryptFilesCommand>
{
public:
    static const char *staticName()
    {
        return "ENCRYPT_FILES";
    }
    unsigned int operation() const override
    {
        return SignAllowed | EncryptSelected;
    }
};

class SignFilesCommand : public Kleo::AssuanCommandMixin<SignFilesCommand, SignEncryptFilesCommand>
{
public:
    static const char *staticName()
    {
        return "SIGN_FILES";
    }
    unsigned int operation() const override
    {
        return SignSelected | EncryptAllowed;
    }
};

}
