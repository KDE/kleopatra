/*
    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2008 Klarälvdalens Datakonsult AB

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#pragma once

#include "commands/command.h"

#include "utils/types.h"

#include <QStringList>

namespace Kleo
{
namespace Commands
{

class DecryptVerifyFilesCommand : public Command
{
    Q_OBJECT
public:
    explicit DecryptVerifyFilesCommand(QAbstractItemView *view, KeyListController *parent);
    explicit DecryptVerifyFilesCommand(KeyListController *parent);
    explicit DecryptVerifyFilesCommand(const QStringList &files, QAbstractItemView *view, KeyListController *parent);
    explicit DecryptVerifyFilesCommand(const QStringList &files, KeyListController *parent);
    ~DecryptVerifyFilesCommand() override;

    void setFiles(const QStringList &files);

    void setOperation(DecryptVerifyOperation operation);
    DecryptVerifyOperation operation() const;

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
