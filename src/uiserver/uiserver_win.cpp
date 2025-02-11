/* -*- mode: c++; c-basic-offset:4 -*-
    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2007 Klarälvdalens Datakonsult AB

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include <config-kleopatra.h>

#include "uiserver_p.h"

#include <Libkleo/GnuPG>

#include <KLocalizedString>

#include <stdexcept>

#include <io.h>
#include <windows.h>
#include <winsock2.h>

#include <cstdlib>
#include <cstring>

using namespace Kleo;

QString UiServer::Private::systemErrorString()
{
    return QString::fromLocal8Bit(strerror(errno));
}

void UiServer::Private::doMakeListeningSocket(const QByteArray &encodedFileName)
{
    // Create a Unix Domain Socket:
    const assuan_fd_t sock = assuan_sock_new(AF_UNIX, SOCK_STREAM, 0);
    if (sock == ASSUAN_INVALID_FD) {
        throw_<std::runtime_error>(i18n("Could not create socket: %1", systemErrorString()));
    }

    try {
        // Bind
        struct sockaddr_un sa;
        std::memset(&sa, 0, sizeof(sa));
        sa.sun_family = AF_UNIX;
        std::strncpy(sa.sun_path, encodedFileName.constData(), sizeof(sa.sun_path) - 1);
        if (assuan_sock_bind(sock, (struct sockaddr *)&sa, sizeof(sa))) {
            throw_<std::runtime_error>(i18n("Could not bind to socket: %1", systemErrorString()));
        }

        if (assuan_sock_get_nonce((struct sockaddr *)&sa, sizeof(sa), &nonce)) {
            throw_<std::runtime_error>(i18n("Could not get socket nonce: %1", systemErrorString()));
        }

        // Listen
        if (::listen((SOCKET)sock, SOMAXCONN)) {
            throw_<std::runtime_error>(i18n("Could not listen to socket: %1", systemErrorString()));
        }

        if (!setSocketDescriptor((intptr_t)sock)) {
            throw_<std::runtime_error>(i18n("Could not pass socket to Qt: %1. This should not happen, please report this bug.", errorString()));
        }

    } catch (...) {
        assuan_sock_close(sock);
        throw;
    }
}
