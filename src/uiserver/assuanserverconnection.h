/*
    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2007 Klarälvdalens Datakonsult AB

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#pragma once

#include <QObject>

#include <assuan.h> // for assuan_fd_t

#include <memory>
#include <string>
#include <vector>

namespace Kleo
{

class AssuanCommandFactory;

class AssuanServerConnection : public QObject
{
    Q_OBJECT
public:
    AssuanServerConnection(assuan_fd_t fd, const std::vector<std::shared_ptr<AssuanCommandFactory>> &factories, QObject *parent = nullptr);
    ~AssuanServerConnection() override;

public Q_SLOTS:
    void enableCryptoCommands(bool enable = true);

Q_SIGNALS:
    void closed(Kleo::AssuanServerConnection *which);
    void startKeyManagerRequested();
    void startConfigDialogRequested();

public:
    class Private;

private:
    const std::unique_ptr<Private> d;
};

}
