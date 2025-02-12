/*
    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2008 Klarälvdalens Datakonsult AB

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#pragma once

#include <commands/command.h>

#include <QStringList>

namespace Kleo
{
namespace Commands
{

class ImportCrlCommand : public Command
{
    Q_OBJECT
public:
    explicit ImportCrlCommand(QAbstractItemView *view, KeyListController *parent);
    explicit ImportCrlCommand(KeyListController *parent);
    explicit ImportCrlCommand(const QStringList &files, QAbstractItemView *view, KeyListController *parent);
    explicit ImportCrlCommand(const QStringList &files, KeyListController *parent);
    ~ImportCrlCommand() override;

    void setFiles(const QStringList &files);

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
