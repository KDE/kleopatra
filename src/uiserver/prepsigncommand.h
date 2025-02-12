/*
    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2010 Klarälvdalens Datakonsult AB

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#pragma once

#include "assuancommand.h"

#include <memory>

namespace Kleo
{

class PrepSignCommand : public Kleo::AssuanCommandMixin<PrepSignCommand>
{
public:
    PrepSignCommand();
    ~PrepSignCommand() override;

private:
    int doStart() override;
    void doCanceled() override;

public:
    static const char *staticName()
    {
        return "PREP_SIGN";
    }

    class Private;

private:
    const std::unique_ptr<Private> d;
};

}
