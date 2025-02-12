/*
    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2007 Klarälvdalens Datakonsult AB

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#pragma once

namespace Kleo
{

struct WSAStarter {
    const int startupError;

    WSAStarter();
    ~WSAStarter();
};

} // namespace Kleo
