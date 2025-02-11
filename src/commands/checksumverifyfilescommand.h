/* -*- mode: c++; c-basic-offset:4 -*-
    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2008 Klarälvdalens Datakonsult AB

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#pragma once

#include <commands/command.h>

#include <utils/types.h>

#include <gpgme++/global.h>

#include <QStringList>

namespace Kleo
{
namespace Commands
{

class ChecksumVerifyFilesCommand : public Command
{
    Q_OBJECT
public:
    explicit ChecksumVerifyFilesCommand(QAbstractItemView *view, KeyListController *parent);
    explicit ChecksumVerifyFilesCommand(KeyListController *parent);
    explicit ChecksumVerifyFilesCommand(const QStringList &files, QAbstractItemView *view, KeyListController *parent);
    explicit ChecksumVerifyFilesCommand(const QStringList &files, KeyListController *parent);
    ~ChecksumVerifyFilesCommand() override;

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
