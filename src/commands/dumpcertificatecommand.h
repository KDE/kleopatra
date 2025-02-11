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

class DumpCertificateCommand : public Command
{
    Q_OBJECT
public:
    explicit DumpCertificateCommand(QAbstractItemView *view, KeyListController *parent);
    explicit DumpCertificateCommand(KeyListController *parent);
    explicit DumpCertificateCommand(const GpgME::Key &key);
    ~DumpCertificateCommand() override;

    static Restrictions restrictions()
    {
        return OnlyOneKey | MustBeCMS;
    }

    void setUseDialog(bool on);
    bool useDialog() const;

    QStringList output() const;

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
