/*
    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2021 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include <config-kleopatra.h>

#include "accessiblerichtextlabel_p.h"

#include "accessiblelink_p.h"

#include <interfaces/anchorprovider.h>

#include <QLabel>
#include <QTextDocument>

using namespace Kleo;

struct AccessibleRichTextLabel::ChildData {
    QAccessible::Id id = 0;
};

AccessibleRichTextLabel::AccessibleRichTextLabel(QWidget *w)
    : QAccessibleWidget{w, QAccessible::StaticText}
{
    Q_ASSERT(qobject_cast<QLabel *>(w));
}

AccessibleRichTextLabel::~AccessibleRichTextLabel()
{
    clearChildCache();
}

void *AccessibleRichTextLabel::interface_cast(QAccessible::InterfaceType t)
{
    if (t == QAccessible::TextInterface) {
        return static_cast<QAccessibleTextInterface *>(this);
    }
    return QAccessibleWidget::interface_cast(t);
}

QAccessible::State AccessibleRichTextLabel::state() const
{
    QAccessible::State state = QAccessibleWidget::state();
    state.readOnly = true;
    state.selectableText = true;
    return state;
}

QString AccessibleRichTextLabel::text(QAccessible::Text t) const
{
    QString str;
    switch (t) {
    case QAccessible::Name:
        str = widget()->accessibleName();
        if (str.isEmpty()) {
            str = displayText();
        }
        break;
    default:
        break;
    }
    if (str.isEmpty()) {
        str = QAccessibleWidget::text(t);
    }
    return str;
}

QAccessibleInterface *AccessibleRichTextLabel::focusChild() const
{
    if (const auto *const ap = anchorProvider()) {
        const int childIndex = ap->selectedAnchor();
        if (childIndex >= 0) {
            return child(childIndex);
        }
    }
    return QAccessibleWidget::focusChild();
}

QAccessibleInterface *AccessibleRichTextLabel::child(int index) const
{
    const auto *const ap = anchorProvider();
    if (ap && index >= 0 && index < ap->numberOfAnchors()) {
        auto &childData = childCache()[index];
        if (childData.id != 0) {
            return QAccessible::accessibleInterface(childData.id);
        }

        QAccessibleInterface *iface = new AccessibleLink{widget(), index};
        childData.id = QAccessible::registerAccessibleInterface(iface);
        return iface;
    }
    return nullptr;
}

int AccessibleRichTextLabel::childCount() const
{
    if (const auto *const ap = anchorProvider()) {
        return ap->numberOfAnchors();
    }
    return 0;
}

int AccessibleRichTextLabel::indexOfChild(const QAccessibleInterface *child) const
{
    if ((child->role() == QAccessible::Link) && (child->parent() == this)) {
        return static_cast<const AccessibleLink *>(child)->index();
    }
    return -1;
}

void AccessibleRichTextLabel::selection(int selectionIndex, int *startOffset, int *endOffset) const
{
    *startOffset = *endOffset = 0;
    if (selectionIndex != 0)
        return;

    *startOffset = label()->selectionStart();
    *endOffset = *startOffset + label()->selectedText().size();
}

int AccessibleRichTextLabel::selectionCount() const
{
    return label()->hasSelectedText() ? 1 : 0;
}

void AccessibleRichTextLabel::addSelection(int startOffset, int endOffset)
{
    setSelection(0, startOffset, endOffset);
}

void AccessibleRichTextLabel::removeSelection(int selectionIndex)
{
    if (selectionIndex != 0)
        return;

    label()->setSelection(-1, -1);
}

void AccessibleRichTextLabel::setSelection(int selectionIndex, int startOffset, int endOffset)
{
    if (selectionIndex != 0)
        return;

    label()->setSelection(startOffset, endOffset - startOffset);
}

int AccessibleRichTextLabel::cursorPosition() const
{
    return label()->hasSelectedText() ? label()->selectionStart() + label()->selectedText().size() : 0;
}

void AccessibleRichTextLabel::setCursorPosition(int position)
{
    Q_UNUSED(position)
}

QString AccessibleRichTextLabel::text(int startOffset, int endOffset) const
{
    if (startOffset > endOffset)
        return {};

    // most likely the client is asking for the selected text, so return it
    // instead of a slice of displayText() if the offsets match the selection
    if (startOffset == label()->selectionStart() //
        && endOffset == startOffset + label()->selectedText().size()) {
        return label()->selectedText();
    }
    return displayText().mid(startOffset, endOffset - startOffset);
}

int AccessibleRichTextLabel::characterCount() const
{
    return displayText().size();
}

QRect AccessibleRichTextLabel::characterRect(int offset) const
{
    Q_UNUSED(offset)
    return {};
}

int AccessibleRichTextLabel::offsetAtPoint(const QPoint &point) const
{
    Q_UNUSED(point)
    return -1;
}

QString AccessibleRichTextLabel::attributes(int offset, int *startOffset, int *endOffset) const
{
    *startOffset = *endOffset = offset;
    return {};
}

void AccessibleRichTextLabel::scrollToSubstring(int startIndex, int endIndex)
{
    Q_UNUSED(startIndex)
    Q_UNUSED(endIndex)
}

QLabel *AccessibleRichTextLabel::label() const
{
    return qobject_cast<QLabel *>(object());
}

AnchorProvider *AccessibleRichTextLabel::anchorProvider() const
{
    return dynamic_cast<AnchorProvider *>(object());
}

QString AccessibleRichTextLabel::displayText() const
{
    // calculate an approximation of the displayed text without using private
    // information of QLabel
    QString str = label()->text();
    if (label()->textFormat() == Qt::RichText //
        || (label()->textFormat() == Qt::AutoText && Qt::mightBeRichText(str))) {
        QTextDocument doc;
        doc.setHtml(str);
        str = doc.toPlainText();
    }
    return str;
}

std::vector<AccessibleRichTextLabel::ChildData> &AccessibleRichTextLabel::childCache() const
{
    const auto *const ap = anchorProvider();
    if (!ap || static_cast<int>(mChildCache.size()) == ap->numberOfAnchors()) {
        return mChildCache;
    }

    clearChildCache();
    // fill the cache with default-initialized child data
    mChildCache.resize(ap->numberOfAnchors());

    return mChildCache;
}

void AccessibleRichTextLabel::clearChildCache() const
{
    std::for_each(std::cbegin(mChildCache), std::cend(mChildCache), [](const auto &child) {
        if (child.id != 0) {
            QAccessible::deleteAccessibleInterface(child.id);
        }
    });
    mChildCache.clear();
}
