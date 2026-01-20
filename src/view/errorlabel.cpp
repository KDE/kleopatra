/*
    view/errorlabel.cpp

    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2022 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include <config-kleopatra.h>

#include "errorlabel.h"

#include <KColorScheme>

using namespace Kleo;

ErrorLabel::ErrorLabel(QWidget *parent)
    : QLabel{parent}
{
    QPalette palette;
    for (int i = 0; i < QPalette::NColorGroups; ++i) {
        const auto cg = static_cast<QPalette::ColorGroup>(i);
        const auto colors = KColorScheme(cg, KColorScheme::View);
        palette.setBrush(cg, QPalette::Window, colors.background(KColorScheme::NegativeBackground));
        palette.setBrush(cg, QPalette::WindowText, colors.foreground(KColorScheme::NegativeText));
    }
    setPalette(palette);
}

ErrorLabel::~ErrorLabel() = default;
