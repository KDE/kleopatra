/*
    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2021 g10 Code GmbH

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#pragma once

#include <windows.h>
#define SECURITY_WIN32
#include <security.h> // For GetUserNameEx

#include <QString>

QString win_get_user_name(EXTENDED_NAME_FORMAT what);

bool win_user_is_elevated();
