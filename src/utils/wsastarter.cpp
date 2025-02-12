/*
    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2007 Klarälvdalens Datakonsult AB

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include <config-kleopatra.h>

#include "wsastarter.h"

using namespace Kleo;

#ifdef _WIN32
#include <winsock2.h>
#else
using WSADATA = int;
static inline int WSAStartup(int, int *)
{
    return 0;
}
static inline void WSACleanup()
{
}
#endif

static int startWSA()
{
    WSADATA dummy;
    return WSAStartup(0x202, &dummy);
}

WSAStarter::WSAStarter()
    : startupError(startWSA())
{
}

WSAStarter::~WSAStarter()
{
    if (!startupError) {
        WSACleanup();
    }
}
