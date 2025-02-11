/*
    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2024 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include "winapi-helpers.h"

#include <QColor>

#include <windows.h>

QColor win_getSysColor(int index)
{
    DWORD color = GetSysColor(index);
    return QColor{GetRValue(color), GetGValue(color), GetBValue(color)};
}
