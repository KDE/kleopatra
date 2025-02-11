/*
    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2021 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#pragma once

class QString;

namespace Kleo
{
/* Tries to obtain the users full name from the
 * operating system to be useable for Key creation. */
QString userFullName();

/* Tries to obtain the users email from the
 * operating system to be useable for Key creation. */
QString userEmailAddress();

/* Checks if the user is running with an elevated security
 * token. This is only a concept of Windows and returns
 * false on other platforms. */
bool userIsElevated();
}
