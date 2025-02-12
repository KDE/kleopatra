/*
    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2008 Klarälvdalens Datakonsult AB

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#pragma once

#include <commands/command.h>

#include <gpgme++/global.h>

namespace Kleo
{
namespace Commands
{

class NewCertificateSigningRequestCommand : public Command
{
    Q_OBJECT
public:
    NewCertificateSigningRequestCommand();
    NewCertificateSigningRequestCommand(QAbstractItemView *view, KeyListController *parent);
    ~NewCertificateSigningRequestCommand() override;

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
