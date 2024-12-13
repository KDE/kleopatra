/*
    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2008 Klarälvdalens Datakonsult AB
    SPDX-FileCopyrightText: 2025 g10 Code GmbH
    SPDX-FileContributor: Tobias Fella <tobias.fella@gnupg.com>

    SPDX-License-Identifier: GPL-2.0-or-later
*/
#pragma once

#include <commands/command.h>

#ifndef QT_NO_CLIPBOARD

namespace Kleo
{
namespace Commands
{

class SignEncryptClipboardCommand : public Command
{
    Q_OBJECT

public:
    enum class Mode {
        SignEncrypt,
        Sign,
        Encrypt,
    };
    explicit SignEncryptClipboardCommand(SignEncryptClipboardCommand::Mode mode = SignEncryptClipboardCommand::Mode::SignEncrypt);

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
