/*
    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2022 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#pragma once

class QWidget;

namespace Kleo
{

/// debug-logs the widget chain defined by QWidget::nextInFocusChain()
void dumpFocusChain(QWidget *window);

/// debug-logs the widgets that would get focus by contiuous tabbing and backtabbing
void dumpTabOrder(QWidget *widget);

}
