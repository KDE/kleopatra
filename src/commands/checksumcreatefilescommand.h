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

class ChecksumCreateFilesCommand : public Command
{
    Q_OBJECT
public:
    explicit ChecksumCreateFilesCommand(QAbstractItemView *view, KeyListController *parent);
    explicit ChecksumCreateFilesCommand(KeyListController *parent);
    explicit ChecksumCreateFilesCommand(const QStringList &files, QAbstractItemView *view, KeyListController *parent);
    explicit ChecksumCreateFilesCommand(const QStringList &files, KeyListController *parent);
    ~ChecksumCreateFilesCommand() override;

    void setFiles(const QStringList &files);

private:
    void doStart() override;
    void doCancel() override;

private:
    class Private;
    inline Private *d_func();
    inline const Private *d_func() const;
    Q_PRIVATE_SLOT(d_func(), void slotControllerDone())
    Q_PRIVATE_SLOT(d_func(), void slotControllerError(int, QString))
};

}
}
