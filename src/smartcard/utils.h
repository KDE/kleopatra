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
enum class AppType;
struct AlgorithmInfo;
class OpenPGPCard;

std::string appName(Kleo::SmartCard::AppType appType);

QString displayAppName(const std::string &appName);

/**
 * Returns a human-readable name for the key slot \p keyRef if such a name is
 * known. Otherwise, returns an empty string.
 */
QString cardKeyDisplayName(const std::string &keyRef);

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
