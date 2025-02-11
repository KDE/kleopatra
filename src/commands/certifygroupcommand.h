/*
    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2023 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#pragma once

#include "command.h"

namespace Kleo
{
class KeyGroup;

class CertifyGroupCommand : public Command
{
    Q_OBJECT
public:
    explicit CertifyGroupCommand(const KeyGroup &group);
    ~CertifyGroupCommand() override;

    /* reimp */ static Restrictions restrictions()
    {
        return MustBeOpenPGP | MustBeValid;
    }

private:
    void doStart() override;
    void doCancel() override;

private:
    class Private;
    inline Private *d_func();
    inline const Private *d_func() const;
};

}
