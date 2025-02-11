/* -*- mode: c++; c-basic-offset:4 -*-
    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2009 Klarälvdalens Datakonsult AB

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#pragma once

#include <QAbstractButton>

class QDialog;
class QDialogButtonBox;
class QWidget;

namespace Kleo
{
static inline void really_check(QAbstractButton &b, bool on)
{
    const bool excl = b.autoExclusive();
    b.setAutoExclusive(false);
    b.setChecked(on);
    b.setAutoExclusive(excl);
}

static inline bool xconnect(const QObject *a, const char *signal, const QObject *b, const char *slot)
{
    return QObject::connect(a, signal, b, slot) && QObject::connect(b, signal, a, slot);
}

/** Aggressively raise a window to foreground. May be platform
 * specific. */
void aggressive_raise(QWidget *w, bool stayOnTop);

/**
 * Puts the second widget after the first widget in the focus order.
 *
 * In contrast to QWidget::setTabOrder(), this function also changes the
 * focus order if the first widget or the second widget has focus policy
 * Qt::NoFocus.
 *
 * Note: After calling this function all widgets in the focus proxy chain
 * of the first widget have focus policy Qt::NoFocus if the first widget
 * has this focus policy. Correspondingly, for the second widget.
 */
void forceSetTabOrder(QWidget *first, QWidget *second);

/**
 * Gives the keyboard input focus to the first of the \p buttons, that is
 * enabled and checked.
 *
 * Returns true, if a button was given focus. Returns false, if no button was
 * found that is enabled and checked.
 */
bool focusFirstCheckedButton(const std::vector<QAbstractButton *> &buttons);

/**
 * Gives the keyboard input focus to the first of the \p buttons, that is
 * enabled.
 *
 * Returns true, if a button was given focus. Returns false, if no button was
 * found that is enabled.
 */
bool focusFirstEnabledButton(const std::vector<QAbstractButton *> &buttons);

/**
 * Unsets the default property of all push buttons in the button box.
 *
 * This function needs to be called after the button box received the show event
 * because QDialogButtonBox automatically sets a default button when it is shown.
 *
 * \sa unsetAutoDefaultButtons
 */
void unsetDefaultButtons(const QDialogButtonBox *buttonBox);

/**
 * Unsets the auto-default property of all push buttons in the dialog.
 *
 * This can be useful if you want to prevent the accidental closing of the dialog
 * when the user presses Enter while another UI element, e.g. a text input field
 * has focus.
 *
 * \sa unsetDefaultButtons
 */
void unsetAutoDefaultButtons(const QDialog *dialog);

class BulkStateChanger
{
public:
    BulkStateChanger();

    void addWidget(QWidget *widget);

    void setVisible(bool visible);

private:
    std::vector<QPointer<QWidget>> mWidgets;
};
}
