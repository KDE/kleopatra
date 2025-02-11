/*
    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2022 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/
#pragma once

#include <QString>

#include <string>

namespace Kleo
{
namespace SmartCard
{

struct AlgorithmInfo {
    std::string id;
    QString displayName;
};

} // namespace SmartCard
} // namespace Kleo
