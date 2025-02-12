/*
    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2021 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#pragma once

#include "command.h"

namespace Kleo
{
class KeyGroup;

class ExportGroupsCommand : public Command
{
    Q_OBJECT
public:
    explicit ExportGroupsCommand(const std::vector<KeyGroup> &groups);
    ~ExportGroupsCommand() override;

private:
    void doStart() override;
    void doCancel() override;

private:
    class Private;
    inline Private *d_func();
    inline const Private *d_func() const;
};
}
