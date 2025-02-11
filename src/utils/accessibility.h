/*
    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2022 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/
#pragma once

#include <QAccessible>
#include <QPointer>

class QAction;
class QLabel;
class QObject;
class QString;

namespace Kleo
{
QString getAccessibleName(QWidget *widget);
QString getAccessibleDescription(QWidget *widget);

/**
 * Sets the accessible name of the action \p action.
 *
 * \note Qt does not provide an accessible object for a QAction. Therefore,
 *       we store the accessible name as custom property of the action.
 * \sa getAccessibleName
 */
void setAccessibleName(QAction *action, const QString &name);
/**
 * Returns the accessible name of the action \p action.
 * \sa setAccessibleName
 */
QString getAccessibleName(const QAction *action);

/**
 * Sets \p value as accessible value of \p widget.
 *
 * Stores the string \p value as custom property of the widget \p widget
 * for retrieval by a QAccessibleWidget.
 *
 * \sa getAccessibleValue
 */
void setAccessibleValue(QWidget *widget, const QString &value);
/**
 * Returns the accessible value of \p widget.
 *
 * \sa setAccessibleValue
 */
QString getAccessibleValue(const QWidget *widget);

/**
 * Mark \p widget as being represented as AccessibleValueWidget.
 *
 * This is useful, if you want Windows UI Automation to treat the widget
 * as labelled value, i.e. a custom widget with a value and a name.
 *
 * \note: Don't use this on other platforms than Windows, unless you made
 *        sure that it works as expected.
 * \sa representAsAccessibleValueWidget
 */
void setRepresentAsAccessibleValueWidget(QWidget *widget, bool);
/**
 * Returns whether \p widget is marked as being represented as
 * AccessibleValueWidget.
 *
 * \sa setRepresentAsAccessibleValueWidget
 */
bool representAsAccessibleValueWidget(const QWidget *widget);

QString invalidEntryText();
QString requiredText();

/**
 * Selects the text displayed by the label. Only \ref QLabel with text format
 * \c Qt::PlainText or \c Qt::RichText are supported.
 */
void selectLabelText(QLabel *label);

/**
 * Simple helper that sets the focus policy of the associated labels
 * to \c Qt::StrongFocus if an assistive tool is active.
 */
class LabelHelper : public QAccessible::ActivationObserver
{
public:
    LabelHelper();
    ~LabelHelper() override;
    Q_DISABLE_COPY_MOVE(LabelHelper)

    void addLabel(QLabel *label);

private:
    void accessibilityActiveChanged(bool active) override;

    std::vector<QPointer<QLabel>> mLabels;
};
}
