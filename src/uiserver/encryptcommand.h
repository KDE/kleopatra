/* -*- mode: c++; c-basic-offset:4 -*-
    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2007 Klarälvdalens Datakonsult AB

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#pragma once

#include "assuancommand.h"

#include <memory>

namespace Kleo
{

class EncryptCommand : public Kleo::AssuanCommandMixin<EncryptCommand>
{
public:
    EncryptCommand();
    ~EncryptCommand() override;

private:
    int doStart() override;
    void doCanceled() override;

public:
    static const char *staticName()
    {
        return "ENCRYPT";
    }

    class Private;

private:
    const std::unique_ptr<Private> d;
};

}
