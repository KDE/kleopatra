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

class SignCommand : public Kleo::AssuanCommandMixin<SignCommand>
{
public:
    SignCommand();
    ~SignCommand() override;

private:
    int doStart() override;
    void doCanceled() override;

public:
    static const char *staticName()
    {
        return "SIGN";
    }

    class Private;

private:
    const std::unique_ptr<Private> d;
};

}
