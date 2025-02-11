/*
    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2016 Bundesamt für Sicherheit in der Informationstechnik
    SPDX-FileCopyrightText: 2024 g10 Code GmbH
    SPDX-FileContributor: Intevation GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include "progressoverlay.h"

#include "waitwidget.h"

using namespace Kleo;

ProgressOverlay::ProgressOverlay(QWidget *baseWidget, QWidget *parent)
    : OverlayWidget{baseWidget, parent}
{
    setOverlay(new WaitWidget{this});
}

ProgressOverlay::~ProgressOverlay() = default;

void ProgressOverlay::setText(const QString &text)
{
    qobject_cast<WaitWidget *>(overlay())->setText(text);
}

QString ProgressOverlay::text() const
{
    return qobject_cast<const WaitWidget *>(overlay())->text();
}

#include "moc_progressoverlay.cpp"
