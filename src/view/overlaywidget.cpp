/*
    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2016 Bundesamt für Sicherheit in der Informationstechnik
    SPDX-FileCopyrightText: 2024 g10 Code GmbH
    SPDX-FileContributor: Intevation GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include "overlaywidget.h"

#include "kleopatra_debug.h"

#include <QApplication>
#include <QEvent>
#include <QLabel>
#include <QVBoxLayout>

using namespace Kleo;

OverlayWidget::OverlayWidget(QWidget *baseWidget, QWidget *parent)
    : QWidget(parent)
    , mBaseWidget(baseWidget)
{
    new QVBoxLayout(this);

    setAutoFillBackground(true);
    auto widgetPalette = palette();
    auto backgroundColor = widgetPalette.color(QPalette::Window);
    backgroundColor.setAlphaF(0.8);
    widgetPalette.setColor(QPalette::Window, backgroundColor);
    setPalette(widgetPalette);
}

OverlayWidget::~OverlayWidget()
{
}

void OverlayWidget::setOverlay(QWidget *widget)
{
    if (mOverlay) {
        delete mOverlay;
    }
    mOverlay = widget;
    setFocusProxy(mOverlay);
    setFocusPolicy(mOverlay->focusPolicy());
    qobject_cast<QVBoxLayout *>(layout())->addWidget(mOverlay);
}

QWidget *Kleo::OverlayWidget::overlay() const
{
    return mOverlay;
}

void OverlayWidget::showOverlay()
{
    if (shown) {
        return;
    }
    shown = true;
    reposition();
    // grab focus if the base widget (or one of its children) has focus
    mOldFocusWidget.clear();
    if ((focusPolicy() != Qt::NoFocus) && (mBaseWidget->hasFocus() || mBaseWidget->isAncestorOf(QApplication::focusWidget()))) {
        mOldFocusWidget = QApplication::focusWidget();
        setFocus();
    }
    mBaseWidget->setEnabled(false);
    mBaseWidget->installEventFilter(this);
}

void OverlayWidget::hideOverlay()
{
    if (!shown) {
        return;
    }
    shown = false;
    mBaseWidget->removeEventFilter(this);
    mBaseWidget->setEnabled(true);
    // return focus to the previous focus widget if the overlay had focus
    if (hasFocus() && mOldFocusWidget) {
        mOldFocusWidget->setFocus();
    }
    hide();
}

bool OverlayWidget::eventFilter(QObject *object, QEvent *event)
{
    if (object == mBaseWidget
        && (event->type() == QEvent::Move || event->type() == QEvent::Resize || event->type() == QEvent::Show || event->type() == QEvent::Hide)) {
        reposition();
    }
    return QWidget::eventFilter(object, event);
}

void OverlayWidget::reposition()
{
    if (parentWidget() != mBaseWidget->window()) {
        setParent(mBaseWidget->window());
    }
    show();

    const QPoint topLevelPos = mBaseWidget->mapTo(window(), QPoint(0, 0));
    const QPoint parentPos = parentWidget()->mapFrom(window(), topLevelPos);
    move(parentPos);

    resize(mBaseWidget->size());
}

#include "moc_overlaywidget.cpp"
