/*
    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2022 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include <config-kleopatra.h>

#include "accessibility.h"

#include <KLocalizedString>

#include <QAction>
#include <QLabel>
#include <QTextDocument>

#include <algorithm>
#include <chrono>

#include "kleopatra_debug.h"

Q_LOGGING_CATEGORY(KLEOPATRA_A11Y_LOG, "org.kde.pim.kleopatra.a11y", QtWarningMsg)

using namespace Kleo;

static const char *accessibleNameProperty = "_kleo_accessibleName";
static const char *accessibleValueProperty = "_kleo_accessibleValue";

static const char *useAccessibleValueLabelProperty = "_kleo_useAccessibleValueLabel";

namespace
{
QString getAccessibleText(QWidget *widget, QAccessible::Text t)
{
    QString name;
    if (const auto *const iface = QAccessible::queryAccessibleInterface(widget)) {
        name = iface->text(t);
    }
    return name;
}
}

QString Kleo::getAccessibleName(QWidget *widget)
{
    return getAccessibleText(widget, QAccessible::Name);
}

QString Kleo::getAccessibleDescription(QWidget *widget)
{
    return getAccessibleText(widget, QAccessible::Description);
}

void Kleo::setAccessibleName(QAction *action, const QString &name)
{
    action->setProperty(accessibleNameProperty, name);
}

QString Kleo::getAccessibleName(const QAction *action)
{
    return action->property(accessibleNameProperty).toString();
}

void Kleo::setAccessibleValue(QWidget *widget, const QString &value)
{
    widget->setProperty(accessibleValueProperty, value);
}

QString Kleo::getAccessibleValue(const QWidget *widget)
{
    return widget->property(accessibleValueProperty).toString();
}

void Kleo::setRepresentAsAccessibleValueWidget(QWidget *widget, bool flag)
{
    widget->setProperty(useAccessibleValueLabelProperty, flag ? flag : QVariant{});
}

bool Kleo::representAsAccessibleValueWidget(const QWidget *widget)
{
    return widget->property(useAccessibleValueLabelProperty).toBool();
}

QString Kleo::invalidEntryText()
{
    return i18nc(
        "text for screen readers to indicate that the associated object, "
        "such as a form field, has an error",
        "invalid entry");
}

QString Kleo::requiredText()
{
    return i18nc(
        "text for screen readers to indicate that the associated object, "
        "such as a form field must be filled out",
        "required");
}

void Kleo::selectLabelText(QLabel *label)
{
    if (!label || label->text().isEmpty()) {
        return;
    }
    if (label->textFormat() == Qt::PlainText) {
        label->setSelection(0, label->text().size());
    } else if (label->textFormat() == Qt::RichText) {
        // unfortunately, there is no selectAll(); therefore, we need
        // to determine the "visual" length of the text by stripping
        // the label's text of all formatting information
        QTextDocument temp;
        temp.setHtml(label->text());
        label->setSelection(0, temp.toRawText().size());
    } else {
        qCDebug(KLEOPATRA_LOG) << "Label with unsupported text format" << label->textFormat() << "got focus";
    }
}

LabelHelper::LabelHelper()
{
    QAccessible::installActivationObserver(this);
}

LabelHelper::~LabelHelper()
{
    QAccessible::removeActivationObserver(this);
}

void LabelHelper::addLabel(QLabel *label)
{
    mLabels.push_back(label);
    accessibilityActiveChanged(QAccessible::isActive());
}

void LabelHelper::accessibilityActiveChanged(bool active)
{
    // Allow text labels to get focus if accessibility is active
    const auto focusPolicy = active ? Qt::StrongFocus : Qt::ClickFocus;
    std::for_each(std::cbegin(mLabels), std::cend(mLabels), [focusPolicy](const auto &label) {
        if (label) {
            label->setFocusPolicy(focusPolicy);
        }
    });
}

static void accessibleUpdateHandler(QAccessibleEvent *event)
{
    qCDebug(KLEOPATRA_A11Y_LOG) << event->object() << event->child() << event->type();
    QAccessible::installUpdateHandler(nullptr);
    QAccessible::updateAccessibility(event);
    QAccessible::installUpdateHandler(&accessibleUpdateHandler);
}

void Kleo::installAccessibleEventLogger()
{
    qCDebug(KLEOPATRA_LOG) << __func__ << "Installing accessible update handler";
    QAccessible::installUpdateHandler(&accessibleUpdateHandler);
}
