/* -*- mode: c++; c-basic-offset:4 -*-
    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2008 Klarälvdalens Datakonsult AB

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#pragma once

#include <commands/command.h>

namespace Kleo
{
namespace Commands
{

class DumpCrlCacheCommand : public Command
{
    Q_OBJECT
public:
    explicit DumpCrlCacheCommand(QAbstractItemView *view, KeyListController *parent);
    explicit DumpCrlCacheCommand(KeyListController *parent);
    ~DumpCrlCacheCommand() override;

private:
    void doStart() override;
    void doCancel() override;

private:
    class Private;
    inline Private *d_func();
    inline const Private *d_func() const;
};

}
}
