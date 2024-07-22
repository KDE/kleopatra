/*  utils/tags.h

    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2019 g10code GmbH

    SPDX-License-Identifier: GPL-2.0-or-later
*/
#pragma once

#include <gpgme++/key.h>

#include <vector>

namespace Kleo
{
namespace Tags
{
/* Get multiple keys to use for tags. Currently
 * this returns all fully trusted OpenPGP Keys. */
std::vector<GpgME::Key> tagKeys();
}
} // namespace Kleo
