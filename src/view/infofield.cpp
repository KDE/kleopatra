/*  view/infofield.cpp

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
    , mLayout{new QHBoxLayout}
    , mIcon{new QLabel{parent}}
    , mValue{new QLabel{parent}}
    , mButton{new QPushButton{parent}}
{
    mLabel->setObjectName(QStringLiteral("InfoField.label"));
    mIcon->setObjectName(QStringLiteral("InfoField.icon"));
    mValue->setObjectName(QStringLiteral("InfoField.value"));
    mButton->setObjectName(QStringLiteral("InfoField.button"));

    mLabel->setBuddy(mValue);
    mLabel->setTextInteractionFlags(Qt::TextSelectableByMouse);
    mIcon->setVisible(false);
    mLayout->addWidget(mIcon);
    mValue->setTextInteractionFlags(Qt::TextSelectableByMouse);
    mValue->setFocusPolicy(Qt::TabFocus);
#ifdef Q_OS_WIN
    Kleo::setRepresentAsAccessibleValueWidget(mValue, true);
#endif
    mLayout->addWidget(mValue);
    mButton->setSizePolicy(QSizePolicy::Fixed, QSizePolicy::Fixed);
    mButton->setVisible(false);
    mLayout->addWidget(mButton);
    mLayout->addStretch();
}

QLabel *InfoField::label() const
{
    return mLabel;
}

QLayout *InfoField::layout() const
{
    return mLayout;
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
    mIcon->setVisible(visible && !mIcon->pixmap(Qt::ReturnByValue).isNull());
    mValue->setVisible(visible);
    mButton->setVisible(visible && mAction);
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
