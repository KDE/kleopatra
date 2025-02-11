/*
    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2022 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include <config-kleopatra.h>

#include "accessiblelink_p.h"

#include <interfaces/anchorprovider.h>

#include <QWidget>

using namespace Kleo;

AccessibleLink::AccessibleLink(QWidget *label, int index)
    : mLabel{label}
    , mIndex{index}
{
}

AccessibleLink::~AccessibleLink() = default;

bool AccessibleLink::isValid() const
{
    return mLabel;
}

QObject *AccessibleLink::object() const
{
    return nullptr;
}

QWindow *AccessibleLink::window() const
{
    if (auto p = parent()) {
        return p->window();
    }
    return nullptr;
}

QAccessibleInterface *AccessibleLink::childAt(int, int) const
{
    return nullptr;
}

QAccessibleInterface *AccessibleLink::parent() const
{
    return QAccessible::queryAccessibleInterface(mLabel);
}

QAccessibleInterface *AccessibleLink::child(int) const
{
    return nullptr;
}

int AccessibleLink::childCount() const
{
    return 0;
}

int AccessibleLink::indexOfChild(const QAccessibleInterface *) const
{
    return -1;
}

QString AccessibleLink::text(QAccessible::Text t) const
{
    QString str;
    switch (t) {
    case QAccessible::Name:
        if (auto ap = anchorProvider()) {
            str = ap->anchorText(mIndex);
        }
        break;
    default:
        break;
    }
    return str;
}

void AccessibleLink::setText(QAccessible::Text /*t*/, const QString & /*text */)
{
}

QRect AccessibleLink::rect() const
{
    if (auto p = parent()) {
        return p->rect();
    }
    return {};
}

QAccessible::Role AccessibleLink::role() const
{
    return QAccessible::Link;
}

QAccessible::State AccessibleLink::state() const
{
    QAccessible::State s;
    if (auto p = parent()) {
        s = p->state();
    }
    if (auto ap = anchorProvider()) {
        s.focused = ap->selectedAnchor() == mIndex;
    }
    return s;
}

void *AccessibleLink::interface_cast(QAccessible::InterfaceType t)
{
    if (t == QAccessible::ActionInterface) {
        return static_cast<QAccessibleActionInterface *>(this);
    }
    return nullptr;
}

QStringList AccessibleLink::actionNames() const
{
    return {pressAction()};
}

void AccessibleLink::doAction(const QString &actionName)
{
    if (actionName == pressAction()) {
        if (auto ap = anchorProvider()) {
            ap->activateAnchor(mIndex);
        }
    }
}

QStringList AccessibleLink::keyBindingsForAction(const QString &) const
{
    return {};
}

int AccessibleLink::index() const
{
    return mIndex;
}

AnchorProvider *AccessibleLink::anchorProvider() const
{
    return dynamic_cast<AnchorProvider *>(mLabel.data());
}
