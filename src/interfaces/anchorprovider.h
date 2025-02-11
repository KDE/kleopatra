/* -*- mode: c++; c-basic-offset:4 -*-
    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2022 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#pragma once

#include <Qt>

namespace Kleo
{

class AnchorProvider
{
public:
    virtual ~AnchorProvider() = default;

    virtual int numberOfAnchors() const = 0;
    virtual QString anchorText(int index) const = 0;
    virtual QString anchorHref(int index) const = 0;
    virtual void activateAnchor(int index) = 0;
    virtual int selectedAnchor() const = 0;
};

}
