/*
    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2022 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include <config-kleopatra.h>

#include "infofield.h"

#include "utils/accessibility.h"

#include <QAction>
#include <QHBoxLayout>
#include <QIcon>
#include <QLabel>
#include <QLayout>
#include <QPushButton>
#include <QStyle>

using namespace Kleo;

InfoField::InfoField(const QString &label, QWidget *parent)
    : mLabel{new QLabel{label, parent}}
    , mValueWidget{new QWidget{parent}}
    , mIcon{new QLabel{mValueWidget}}
    , mValue{new QLabel{mValueWidget}}
    , mButton{new QPushButton{mValueWidget}}
{
    mLabel->setObjectName(QLatin1StringView("InfoField.label"));
    mIcon->setObjectName(QLatin1StringView("InfoField.icon"));
    mValue->setObjectName(QLatin1StringView("InfoField.value"));
    mButton->setObjectName(QLatin1StringView("InfoField.button"));

    auto layout = new QHBoxLayout(mValueWidget);
    layout->setContentsMargins({});

    mLabel->setBuddy(mValue);
    mLabel->setTextInteractionFlags(Qt::TextSelectableByMouse);
    mIcon->setVisible(false);
    layout->addWidget(mIcon);
    mValue->setTextInteractionFlags(Qt::TextSelectableByMouse);
    mValue->setFocusPolicy(Qt::TabFocus);
#ifdef Q_OS_WIN
    Kleo::setRepresentAsAccessibleValueWidget(mValue, true);
#endif
    layout->addWidget(mValue);
    mButton->setSizePolicy(QSizePolicy::Fixed, QSizePolicy::Fixed);
    mButton->setVisible(false);
    layout->addWidget(mButton);
    layout->addStretch();
}

QLabel *InfoField::label() const
{
    return mLabel;
}

QWidget *InfoField::valueWidget() const
{
    return mValueWidget;
}

QLabel *InfoField::valueLabel() const
{
    return mValue;
}

void InfoField::setValue(const QString &value, const QString &accessibleValue)
{
    mValue->setText(value);
#ifdef Q_OS_WIN
    Kleo::setAccessibleValue(mValue, accessibleValue);
#else
    mValue->setAccessibleName(accessibleValue);
#endif
}

QString InfoField::value() const
{
    return mValue->text();
}

void InfoField::setIcon(const QIcon &icon)
{
    if (!icon.isNull()) {
        const int iconSize = mIcon->style()->pixelMetric(QStyle::PM_SmallIconSize, nullptr, mIcon);
        mIcon->setPixmap(icon.pixmap(iconSize));
        mIcon->setVisible(true);
    } else {
        mIcon->setVisible(false);
        mIcon->clear();
    }
}

void InfoField::setAction(const QAction *action)
{
    if (action == mAction) {
        return;
    }
    if (mAction) {
        QObject::disconnect(mButton, {}, mAction, {});
        QObject::disconnect(mAction, {}, mButton, {});
    }
    mAction = action;
    if (mAction) {
        QObject::connect(mButton, &QPushButton::clicked, action, &QAction::trigger);
        QObject::connect(mAction, &QAction::changed, mButton, [this]() {
            onActionChanged();
        });
        onActionChanged();
        mButton->setAccessibleName(getAccessibleName(mAction));
        mButton->setVisible(true);
    } else {
        mButton->setVisible(false);
        mButton->setText({});
        mButton->setIcon({});
    }
}

void InfoField::setToolTip(const QString &toolTip)
{
    mValue->setToolTip(toolTip);
}

void InfoField::setVisible(bool visible)
{
    mLabel->setVisible(visible);
    mValueWidget->setVisible(visible);
}

void InfoField::onActionChanged()
{
    if (!mAction) {
        return;
    }
    if (mAction->text() != mButton->text()) {
        mButton->setText(mAction->text());
    }
    mButton->setIcon(mAction->icon());
    if (mAction->toolTip() != mButton->toolTip()) {
        mButton->setToolTip(mAction->toolTip());
    }
    if (mAction->isEnabled() != mButton->isEnabled()) {
        mButton->setEnabled(mAction->isEnabled());
    }
}
