/*
    SPDX-FileCopyrightText: 2025 g10 Code GmbH
    SPDX-FileContributor: Sune Stolborg Vuorela <sune@vuorela.dk>

     SPDX-License-Identifier: GPL-2.0-or-later
*/
// Some of our dependent headers needs unistd.h but msvc doesn't offer them
// We only need the subset that is also present in msvc's io.h, 
// so just forward directly there

#pragma once
#include <io.h>
