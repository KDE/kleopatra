/*
    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2008 Klarälvdalens Datakonsult AB

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#pragma once

#include <commands/command.h>

#ifndef QT_NO_CLIPBOARD

#include <utils/types.h>

namespace Kleo
{
namespace Commands
{

class DecryptVerifyClipboardCommand : public Command
{
    Q_OBJECT
public:
    explicit DecryptVerifyClipboardCommand(QAbstractItemView *view, KeyListController *parent);
    explicit DecryptVerifyClipboardCommand(KeyListController *parent);
    ~DecryptVerifyClipboardCommand() override;

    static bool canDecryptVerifyCurrentClipboard();

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

#endif // QT_NO_CLIPBOARD
