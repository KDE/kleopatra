/*
    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2008 Klarälvdalens Datakonsult AB

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#pragma once

#include <commands/command.h>

namespace GpgME
{
class UserID;
}

namespace Kleo
{
namespace Commands
{

class CertifyCertificateCommand : public Command
{
    Q_OBJECT
public:
    explicit CertifyCertificateCommand(QAbstractItemView *view, KeyListController *parent);
    explicit CertifyCertificateCommand(KeyListController *parent);
    explicit CertifyCertificateCommand(const GpgME::Key &key);
    explicit CertifyCertificateCommand(const GpgME::UserID &uid);
    explicit CertifyCertificateCommand(const std::vector<GpgME::UserID> &uids);
    ~CertifyCertificateCommand() override;

    /* reimp */ static Restrictions restrictions()
    {
        return OnlyOneKey | MustBeOpenPGP | MustBeValid;
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
}
