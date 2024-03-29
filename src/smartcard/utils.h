/*  smartcard/utils.h

    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2020 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/
#pragma once

#include <memory>
#include <string>
#include <vector>

class QString;

namespace Kleo
{
namespace SmartCard
{
struct AlgorithmInfo;
class OpenPGPCard;

QString displayAppName(const std::string &appName);

/**
 * Returns the subset of algorithms \p supportedAlgorithms that are compliant.
 */
std::vector<AlgorithmInfo> getAllowedAlgorithms(const std::vector<AlgorithmInfo> &supportedAlgorithms);

/**
 * Returns the ID of the algorithm in the list \p candidates that is preferred
 * over the other candidates.
 */
std::string getPreferredAlgorithm(const std::vector<AlgorithmInfo> &candidates);

} // namespace Smartcard
} // namespace Kleopatra
