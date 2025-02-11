/*
    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2016 Bundesamt für Sicherheit in der Informationstechnik
    SPDX-FileContributor: Intevation GmbH

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include "keycacheoverlay.h"

#include <Libkleo/KeyCache>

#include "kleopatra_debug.h"
#include "waitwidget.h"

#include <KLocalizedString>
#include <QEvent>
#include <QVBoxLayout>

using namespace Kleo;
using namespace Qt::Literals::StringLiterals;

KeyCacheOverlay::KeyCacheOverlay(QWidget *baseWidget, QWidget *parent)
    : QWidget(parent)
    , mBaseWidget(baseWidget)
{
    const auto cache = KeyCache::instance();

    if (cache->initialized()) {
        // Cache initialized so we are not needed.
        deleteLater();
        return;
    }

    auto vLay = new QVBoxLayout(this);

    auto waitWidget = new WaitWidget(this);

    waitWidget->setText("<h3>"_L1 + i18n("Loading certificate cache...") + "</h3>"_L1);

    vLay->addWidget(waitWidget);

    mBaseWidget->installEventFilter(this);
    mBaseWidget->setEnabled(false);
    reposition();

    connect(&mTimer, &QTimer::timeout, this, [this]() {
        // To avoid an infinite show if we miss the keyListingDone signal
        // (Race potential) we use a watchdog timer, too to actively poll
        // the keycache every second. See bug #381910
        if (KeyCache::instance()->initialized()) {
            qCDebug(KLEOPATRA_LOG) << "Hiding overlay from watchdog";
            hideOverlay();
        }
    });

    mTimer.start(1000);

    connect(cache.get(), &KeyCache::keyListingDone, this, &KeyCacheOverlay::hideOverlay);
}

bool KeyCacheOverlay::eventFilter(QObject *object, QEvent *event)
{
    if (object == mBaseWidget
        && (event->type() == QEvent::Move || event->type() == QEvent::Resize || event->type() == QEvent::Show || event->type() == QEvent::Hide)) {
        reposition();
    }
    return QWidget::eventFilter(object, event);
}

void KeyCacheOverlay::reposition()
{
    if (parentWidget() != mBaseWidget->window()) {
        setParent(mBaseWidget->window());
    }
    if (!KeyCache::instance()->initialized()) {
        show();
    }

    const QPoint topLevelPos = mBaseWidget->mapTo(window(), QPoint(0, 0));
    const QPoint parentPos = parentWidget()->mapFrom(window(), topLevelPos);
    move(parentPos);

    resize(mBaseWidget->size());
}

void KeyCacheOverlay::hideOverlay()
{
    mTimer.stop();
    mBaseWidget->setEnabled(true);
    hide();
    mBaseWidget->removeEventFilter(this);
    deleteLater();
}

#include "moc_keycacheoverlay.cpp"
