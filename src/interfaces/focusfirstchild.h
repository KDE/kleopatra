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

class FocusFirstChild
{
public:
    virtual ~FocusFirstChild() = default;

    virtual void focusFirstChild(Qt::FocusReason reason = Qt::OtherFocusReason) = 0;
};

}
