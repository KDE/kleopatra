/*
    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2024 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#pragma once

#include <QString>

namespace Qt
{
inline namespace Literals
{
inline namespace StringLiterals
{
inline QString operator""_s(const char16_t *str, size_t size) noexcept
{
    return QString::fromUtf16(const_cast<char16_t *>(str), int(size));
}
} // StringLiterals
} // Literals
} // Qt
