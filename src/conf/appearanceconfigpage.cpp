/* -*- mode: c++; c-basic-offset:4 -*-
    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2004, 2008 Klarälvdalens Datakonsult AB

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include <config-kleopatra.h>

#include "appearanceconfigpage.h"

#include "appearanceconfigwidget.h"

#include <QVBoxLayout>

using namespace Kleo;
using namespace Kleo::Config;

AppearanceConfigurationPage::AppearanceConfigurationPage(QWidget *parent)
    : KleoConfigModule(parent)
{
    auto lay = new QVBoxLayout(this);
    lay->setContentsMargins({});
    mWidget = new AppearanceConfigWidget(this);
    lay->addWidget(mWidget);

    connect(mWidget, &AppearanceConfigWidget::changed, this, &Kleo::Config::AppearanceConfigurationPage::changed);
}

void AppearanceConfigurationPage::load()
{
    mWidget->load();
}

void AppearanceConfigurationPage::save()
{
    mWidget->save();
}

void AppearanceConfigurationPage::defaults()
{
    mWidget->defaults();
}

#include "moc_appearanceconfigpage.cpp"
