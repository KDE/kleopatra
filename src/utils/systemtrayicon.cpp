/* -*- mode: c++; c-basic-offset:4 -*-
    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2007, 2009 Klarälvdalens Datakonsult AB

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include <config-kleopatra.h>

#include "systemtrayicon.h"

#ifndef QT_NO_SYSTEMTRAYICON

#include "kleopatra_debug.h"
#include <QEvent>
#include <QPointer>
#include <QTimer>
#include <QWidget>

using namespace Kleo;

static const int ATTENTION_ANIMATION_FRAMES_PER_SEC = 1;

class SystemTrayIcon::Private
{
    friend class ::SystemTrayIcon;
    SystemTrayIcon *const q;

public:
    explicit Private(SystemTrayIcon *qq);
    ~Private();

private:
    bool attentionWanted() const
    {
        return attentionAnimationTimer.isActive();
    }

    void setAttentionWantedImpl(bool on)
    {
        if (on) {
            attentionAnimationTimer.start();
        } else {
            attentionAnimationTimer.stop();
            attentionIconShown = false;
            q->setIcon(normalIcon);
        }
    }

    void slotActivated(ActivationReason reason)
    {
        if (reason == QSystemTrayIcon::Trigger) {
            q->doActivated();
        }
    }

    void slotAttentionAnimationTimerTimout()
    {
        if (attentionIconShown) {
            attentionIconShown = false;
            q->setIcon(normalIcon);
        } else {
            attentionIconShown = true;
            q->setIcon(attentionIcon);
        }
    }

private:
    bool attentionIconShown;

    QIcon normalIcon, attentionIcon;

    QTimer attentionAnimationTimer;

    QPointer<QWidget> mainWindow;
    QPointer<QWidget> attentionWindow;
};

SystemTrayIcon::Private::Private(SystemTrayIcon *qq)
    : q(qq)
    , attentionIconShown(false)
    , attentionAnimationTimer()
    , mainWindow()
    , attentionWindow()
{
    Q_SET_OBJECT_NAME(attentionAnimationTimer);

    attentionAnimationTimer.setSingleShot(false);
    attentionAnimationTimer.setInterval(1000 * ATTENTION_ANIMATION_FRAMES_PER_SEC / 2);

    connect(q, &QSystemTrayIcon::activated, q, [this](QSystemTrayIcon::ActivationReason reason) {
        slotActivated(reason);
    });
    connect(&attentionAnimationTimer, &QTimer::timeout, q, [this]() {
        slotAttentionAnimationTimerTimout();
    });
}

SystemTrayIcon::Private::~Private()
{
}

SystemTrayIcon::SystemTrayIcon(QObject *p)
    : QSystemTrayIcon(p)
    , d(new Private(this))
{
}

SystemTrayIcon::SystemTrayIcon(const QIcon &icon, QObject *p)
    : QSystemTrayIcon(icon, p)
    , d(new Private(this))
{
    d->normalIcon = d->attentionIcon = icon;
}

SystemTrayIcon::~SystemTrayIcon()
{
}

void SystemTrayIcon::setMainWindow(QWidget *mw)
{
    if (d->mainWindow) {
        return;
    }
    d->mainWindow = mw;
    if (mw) {
        mw->installEventFilter(this);
    }
    doMainWindowSet(mw);
    slotEnableDisableActions();
}

QWidget *SystemTrayIcon::mainWindow() const
{
    return d->mainWindow;
}

void SystemTrayIcon::setAttentionWindow(QWidget *mw)
{
    if (d->attentionWindow) {
        return;
    }
    d->attentionWindow = mw;
    if (mw) {
        mw->installEventFilter(this);
    }
    slotEnableDisableActions();
}

QWidget *SystemTrayIcon::attentionWindow() const
{
    return d->attentionWindow;
}

bool SystemTrayIcon::eventFilter(QObject *o, QEvent *e)
{
    if (o == d->mainWindow)
        switch (e->type()) {
        case QEvent::Close:
            doMainWindowClosed(static_cast<QWidget *>(o));
            // fall through:
            [[fallthrough]];
        case QEvent::Show:
        case QEvent::DeferredDelete:
            QMetaObject::invokeMethod(this, "slotEnableDisableActions", Qt::QueuedConnection);
        default:;
        }
    else if (o == d->attentionWindow)
        switch (e->type()) {
        case QEvent::Close:
            doAttentionWindowClosed(static_cast<QWidget *>(o));
            // fall through:
            [[fallthrough]];
        case QEvent::Show:
        case QEvent::DeferredDelete:
            QMetaObject::invokeMethod(this, "slotEnableDisableActions", Qt::QueuedConnection);
        default:;
        }
    return false;
}

void SystemTrayIcon::setAttentionWanted(bool on)
{
    if (d->attentionWanted() == on) {
        return;
    }
    qCDebug(KLEOPATRA_LOG) << d->attentionWanted() << "->" << on;
    d->setAttentionWantedImpl(on);
}

bool SystemTrayIcon::attentionWanted() const
{
    return d->attentionWanted();
}

void SystemTrayIcon::setNormalIcon(const QIcon &icon)
{
    if (d->normalIcon.cacheKey() == icon.cacheKey()) {
        return;
    }
    d->normalIcon = icon;
    if (!d->attentionWanted() || !d->attentionIconShown) {
        setIcon(icon);
    }
}

QIcon SystemTrayIcon::normalIcon() const
{
    return d->normalIcon;
}

void SystemTrayIcon::setAttentionIcon(const QIcon &icon)
{
    if (d->attentionIcon.cacheKey() == icon.cacheKey()) {
        return;
    }
    d->attentionIcon = icon;
    if (d->attentionWanted() && d->attentionIconShown) {
        setIcon(icon);
    }
}

QIcon SystemTrayIcon::attentionIcon() const
{
    return d->attentionIcon;
}

void SystemTrayIcon::doMainWindowSet(QWidget *)
{
}
void SystemTrayIcon::doMainWindowClosed(QWidget *)
{
}
void SystemTrayIcon::doAttentionWindowClosed(QWidget *)
{
}

#include "moc_systemtrayicon.cpp"

#endif // QT_NO_SYSTEMTRAYICON
