/* -*- mode: c++; c-basic-offset:4 -*-
    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2008 Klarälvdalens Datakonsult AB

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#pragma once

#include <commands/importcertificatescommand.h>

#include <gpgme++/global.h>

namespace Kleo
{
namespace Commands
{

class LookupCertificatesCommand : public ImportCertificatesCommand
{
    Q_OBJECT
public:
    explicit LookupCertificatesCommand(QAbstractItemView *view, KeyListController *parent);
    explicit LookupCertificatesCommand(KeyListController *parent);
    explicit LookupCertificatesCommand(const QString &fingerPrint, KeyListController *parent);
    ~LookupCertificatesCommand() override;

    void setProtocol(GpgME::Protocol protocol);
    GpgME::Protocol protocol() const;

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
