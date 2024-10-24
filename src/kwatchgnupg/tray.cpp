/*
    main.cpp

    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2001, 2002, 2004 Klarälvdalens Datakonsult AB

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include <config-kleopatra.h>

#include "tray.h"

#include "kwatchgnupgmainwin.h"

#include "kwatchgnupg_debug.h"
#include <KIconUtils>
#include <KLocalizedString>

KWatchGnuPGTray::KWatchGnuPGTray(KWatchGnuPGMainWindow *mainwin)
    : KStatusNotifierItem(mainwin)
{
    qCDebug(KWATCHGNUPG_LOG) << "KWatchGnuPGTray::KWatchGnuPGTray";

    setObjectName(QLatin1StringView("KWatchGnuPG Tray Window"));

    mNormalPix = QIcon::fromTheme(QStringLiteral("org.kde.kwatchgnupg")); // TODO create symbolic version
    mAttentionPix = QIcon(KIconUtils::addOverlay(mNormalPix, QIcon::fromTheme(QStringLiteral("emblem-information")), Qt::BottomLeftCorner).pixmap(48));
    setToolTipTitle(i18n("KWatchGnuPG Log Viewer"));
}

KWatchGnuPGTray::~KWatchGnuPGTray()
{
}

void KWatchGnuPGTray::setAttention(bool att)
{
    if (att) {
        setIconByPixmap(mAttentionPix);
    } else {
        setIconByPixmap(mNormalPix);
    }
}

#include "moc_tray.cpp"
