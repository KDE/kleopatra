/* -*- mode: c++; c-basic-offset:4 -*-
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

class DecryptVerifyCommandFilesBase : public AssuanCommandMixin<DecryptVerifyCommandFilesBase>
{
public:
    enum Flags {
        DecryptOff = 0x0,
        DecryptOn = 0x1,
        DecryptImplied = 0x2,

        DecryptMask = 0x3,

        VerifyOff = 0x00,
        // VerifyOn  = 0x10, // non-sensical
        VerifyImplied = 0x20,

        VerifyMask = 0x30
    };

    explicit DecryptVerifyCommandFilesBase();
    ~DecryptVerifyCommandFilesBase() override;

private:
    virtual DecryptVerifyOperation operation() const = 0;

private:
    int doStart() override;
    void doCanceled() override;

public:
    // ### FIXME fix this
    static const char *staticName()
    {
        return "";
    }

    class Private;

private:
    const std::unique_ptr<Private> d;
};
}
