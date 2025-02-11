/* -*- mode: c++; c-basic-offset:4 -*-
    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2016 Bundesamt für Sicherheit in der Informationstechnik
    SPDX-FileContributor: Intevation GmbH

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#pragma once

#include <commands/command.h>

#include <QProcess>
#include <QString>

class QWidget;

namespace Kleo
{
namespace Commands
{

class ExportPaperKeyCommand : public Command
{
    Q_OBJECT

public:
    explicit ExportPaperKeyCommand(QAbstractItemView *view, KeyListController *parent);
    explicit ExportPaperKeyCommand(const GpgME::Key &key);

    static Restrictions restrictions()
    {
        return OnlyOneKey | NeedSecretPrimaryKeyData | MustBeOpenPGP;
    }

    bool success() const;

private:
    class Private;
    inline Private *d_func();
    inline const Private *d_func() const;
    void doStart() override;
    void doCancel() override;
};

}
}
