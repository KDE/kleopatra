/*
    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2022 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include "labelledwidget.h"

namespace Kleo::_detail
{

QWidget *LabelledWidgetBase::widget() const
{
    return mWidget;
}

QLabel *LabelledWidgetBase::label() const
{
    return mLabel;
}

void LabelledWidgetBase::setWidgets(QWidget *widget, QLabel *label)
{
    mWidget = widget;
    mLabel = label;
    if (mLabel) {
        mLabel->setBuddy(mWidget);
    }
}

void LabelledWidgetBase::setEnabled(bool enabled)
{
    if (mLabel) {
        mLabel->setEnabled(enabled);
    }
    if (mWidget) {
        mWidget->setEnabled(enabled);
    }
}

}
