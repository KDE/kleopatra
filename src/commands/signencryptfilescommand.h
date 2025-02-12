/*
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

class SignEncryptFilesCommand : public Command
{
    Q_OBJECT
public:
    explicit SignEncryptFilesCommand(QAbstractItemView *view, KeyListController *parent);
    explicit SignEncryptFilesCommand(KeyListController *parent);
    explicit SignEncryptFilesCommand(const QStringList &files, QAbstractItemView *view, KeyListController *parent);
    explicit SignEncryptFilesCommand(const QStringList &files, KeyListController *parent);
    ~SignEncryptFilesCommand() override;

    void setFiles(const QStringList &files);

    void setSigningPolicy(Policy policy);
    Policy signingPolicy() const;

    void setEncryptionPolicy(Policy force);
    Policy encryptionPolicy() const;

    void setArchivePolicy(Policy force);
    Policy archivePolicy() const;

    void setProtocol(GpgME::Protocol protocol);
    GpgME::Protocol protocol() const;

protected:
    virtual QStringList selectFiles() const;

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
