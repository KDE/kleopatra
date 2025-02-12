/*
    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2022 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include <config-kleopatra.h>

#include "debug-helpers.h"

#include <QWidget>

#include <kleopatra_debug.h>

static QString indentByWidgetDepth(const QWidget *w)
{
    int indent = 0;
    for (; !w->isWindow(); w = w->parentWidget()) {
        indent += 2;
    }
    return QString{indent, QLatin1Char(' ')};
}

static QWidget *deepestFocusProxy(const QWidget *w)
{
    QWidget *focusProxy = w->focusProxy();
    if (!focusProxy)
        return nullptr;

    while (QWidget *nextFocusProxy = focusProxy->focusProxy())
        focusProxy = nextFocusProxy;

    return focusProxy;
}

void Kleo::dumpFocusChain(QWidget *window)
{
    if (!window) {
        qCDebug(KLEOPATRA_LOG) << __func__ << "Error: window is NULL";
        return;
    }
    qCDebug(KLEOPATRA_LOG) << __func__ << "=====";
    qCDebug(KLEOPATRA_LOG).noquote().nospace() << indentByWidgetDepth(window) << window;
    for (auto w = window->nextInFocusChain(); w != window; w = w->nextInFocusChain()) {
        if (const auto *focusProxy = deepestFocusProxy(w)) {
            qCDebug(KLEOPATRA_LOG).noquote() << indentByWidgetDepth(w) << w << w->focusPolicy() << "proxy:" << focusProxy << focusProxy->focusPolicy();
        } else {
            qCDebug(KLEOPATRA_LOG).noquote() << indentByWidgetDepth(w) << w << w->focusPolicy();
        }
    }
    qCDebug(KLEOPATRA_LOG) << __func__ << "=====";
}

/// returns the widget that QWidget::focusNextPrevChild() would give focus to
static QWidget *simulateFocusNextPrevChild(QWidget *focusWidget, bool next)
{
    // taken from QApplicationPrivate::focusNextPrevChild_helper:
    // uint focus_flag = qt_tab_all_widgets() ? Qt::TabFocus : Qt::StrongFocus;
    uint focus_flag = Qt::TabFocus;

    // QWidget *f = toplevel->focusWidget();
    QWidget *f = focusWidget;
    QWidget *toplevel = focusWidget->window();
    if (!f)
        f = toplevel;

    QWidget *w = f;
    QWidget *test = f->nextInFocusChain();
    // bool seenWindow = false;
    // bool focusWidgetAfterWindow = false;
    while (test && test != f) {
        // if (test->isWindow())
        //     seenWindow = true;

        // If the next focus widget has a focus proxy, we need to check to ensure
        // that the proxy is in the correct parent-child direction (according to
        // \a next). This is to ensure that we can tab in and out of compound widgets
        // without getting stuck in a tab-loop between parent and child.
        QWidget *focusProxy = deepestFocusProxy(test);
        const bool canTakeFocus = ((focusProxy ? focusProxy->focusPolicy() : test->focusPolicy()) & focus_flag) == focus_flag;
        const bool composites = focusProxy ? (next ? focusProxy->isAncestorOf(test) : test->isAncestorOf(focusProxy)) //
                                           : false;
        if (canTakeFocus && !composites //
            && test->isVisibleTo(toplevel) && test->isEnabled() //
            && !(w->windowType() == Qt::SubWindow && !w->isAncestorOf(test)) //
            && (toplevel->windowType() != Qt::SubWindow || toplevel->isAncestorOf(test)) //
            && f != focusProxy) {
            w = test;
            // if (seenWindow)
            //     focusWidgetAfterWindow = true;
            if (next)
                break;
        }
        test = test->nextInFocusChain();
    }

    // if (wrappingOccurred != nullptr)
    //     *wrappingOccurred = next ? focusWidgetAfterWindow : !focusWidgetAfterWindow;

    if (w == f) {
        // if (qt_in_tab_key_event) {
        //     w->window()->setAttribute(Qt::WA_KeyboardFocusChange);
        //     w->update();
        // }
        return nullptr;
    }

    // taken from QWidget::setFocus:
    if (auto focusProxy = deepestFocusProxy(w)) {
        w = focusProxy;
    }

    return w;
}

void Kleo::dumpTabOrder(QWidget *widget)
{
    if (!widget) {
        qCDebug(KLEOPATRA_LOG) << __func__ << "Error: widget is NULL";
        return;
    }
    qCDebug(KLEOPATRA_LOG) << __func__ << "=====";
    // simulate Tab, Tab, Tab, ...
    QSet<QWidget *> seen;
    qCDebug(KLEOPATRA_LOG).noquote().nospace() << indentByWidgetDepth(widget) << widget;
    for (auto w = simulateFocusNextPrevChild(widget, true); w && !seen.contains(w); w = simulateFocusNextPrevChild(w, true)) {
        qCDebug(KLEOPATRA_LOG).noquote().nospace() << indentByWidgetDepth(w) << w;
        seen.insert(w);
    }
    qCDebug(KLEOPATRA_LOG) << __func__ << "=====";
    // simulate Shift+Tab, Shift+Tab, Shift+Tab, ...
    seen.clear();
    qCDebug(KLEOPATRA_LOG).noquote().nospace() << indentByWidgetDepth(widget) << widget;
    for (auto w = simulateFocusNextPrevChild(widget, false); w && !seen.contains(w); w = simulateFocusNextPrevChild(w, false)) {
        qCDebug(KLEOPATRA_LOG).noquote().nospace() << indentByWidgetDepth(w) << w;
        seen.insert(w);
    }
    qCDebug(KLEOPATRA_LOG) << __func__ << "=====";
}
