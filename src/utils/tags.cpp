/*  utils/tags.cpp

    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2019 g10code GmbH

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include "tags.h"

#include <KSharedConfig>
#include <Libkleo/KeyCache>

using namespace Kleo;

std::vector<GpgME::Key> Tags::tagKeys()
{
    std::vector<GpgME::Key> ret;
    for (const auto &key : KeyCache::instance()->keys()) {
        if (key.isNull() || key.isRevoked() || key.isExpired() || key.isDisabled() || key.isInvalid() || key.protocol() != GpgME::OpenPGP) {
            continue;
        }
        if (key.ownerTrust() >= GpgME::Key::Full) {
            ret.push_back(key);
        }
    }
    return ret;
}
