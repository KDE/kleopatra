/*
    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2021 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#pragma once

#include <QAccessibleWidget>

class QLabel;

namespace Kleo
{
class AnchorProvider;

class AccessibleRichTextLabel : public QAccessibleWidget, public QAccessibleTextInterface
{
public:
    explicit AccessibleRichTextLabel(QWidget *o);
    ~AccessibleRichTextLabel() override;

    void *interface_cast(QAccessible::InterfaceType t) override;
    QAccessible::State state() const override;
    QString text(QAccessible::Text t) const override;

    // relations
    QAccessibleInterface *focusChild() const override;

    // navigation, hierarchy
    QAccessibleInterface *child(int index) const override;
    int childCount() const override;
    int indexOfChild(const QAccessibleInterface *child) const override;

    // QAccessibleTextInterface
    // selection
    void selection(int selectionIndex, int *startOffset, int *endOffset) const override;
    int selectionCount() const override;
    void addSelection(int startOffset, int endOffset) override;
    void removeSelection(int selectionIndex) override;
    void setSelection(int selectionIndex, int startOffset, int endOffset) override;

    // cursor
    int cursorPosition() const override;
    void setCursorPosition(int position) override;

    // text
    QString text(int startOffset, int endOffset) const override;
    int characterCount() const override;

    // character <-> geometry
    QRect characterRect(int offset) const override;
    int offsetAtPoint(const QPoint &point) const override;

    void scrollToSubstring(int startIndex, int endIndex) override;
    QString attributes(int offset, int *startOffset, int *endOffset) const override;

private:
    struct ChildData;

    QLabel *label() const;
    AnchorProvider *anchorProvider() const;
    QString displayText() const;

    std::vector<ChildData> &childCache() const;
    void clearChildCache() const;

    mutable std::vector<ChildData> mChildCache;
};

}
