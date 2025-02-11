/* -*- mode: c++; c-basic-offset:4 -*-
    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2007 Klarälvdalens Datakonsult AB

    SPDX-License-Identifier: GPL-2.0-or-later
*/
#pragma once

#include "uiserver.h"

#include "assuancommand.h"
#include "assuanserverconnection.h"

#include <utils/wsastarter.h>

#include <QFile>
#include <QTcpServer>

#include <assuan.h>

#include <algorithm>
#include <memory>
#include <vector>

namespace
{
template<typename Ex>
void throw_(const QString &message)
{
    throw Ex(message.toUtf8().constData());
}
}

namespace Kleo
{

class UiServer::Private : public QTcpServer
{
    Q_OBJECT
    friend class ::Kleo::UiServer;
    UiServer *const q;

public:
    explicit Private(UiServer *qq);
    static bool isStaleAssuanSocket(const QString &socketName);

private:
    void makeListeningSocket();
    // platform-specific creation impl for makeListeningSocket():
    void doMakeListeningSocket(const QByteArray &encodedFileName);
    QString makeFileName(const QString &hint = QString()) const;
    void ensureDirectoryExists(const QString &path) const;
    static QString systemErrorString();

protected:
    void incomingConnection(qintptr fd) override;

private Q_SLOTS:
    void slotConnectionClosed(Kleo::AssuanServerConnection *conn);

private:
    QFile file;
    std::vector<std::shared_ptr<AssuanCommandFactory>> factories;
    std::vector<std::shared_ptr<AssuanServerConnection>> connections;
    QString suggestedSocketName;
    QString actualSocketName;
    assuan_sock_nonce_t nonce;
    const WSAStarter _wsastarter;
    bool cryptoCommandsEnabled;
};

}
