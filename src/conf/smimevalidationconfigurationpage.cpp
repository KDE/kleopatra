/* -*- mode: c++; c-basic-offset:4 -*-
    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2008 Klarälvdalens Datakonsult AB

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include <config-kleopatra.h>

#include "smimevalidationconfigurationpage.h"
#include "smimevalidationconfigurationwidget.h"

#include <QVBoxLayout>

using namespace Kleo::Config;

SMimeValidationConfigurationPage::SMimeValidationConfigurationPage(QWidget *parent)
    : KleoConfigModule(parent)
{
    auto lay = new QVBoxLayout(this);
    lay->setContentsMargins(0, 0, 0, 0);

    mWidget = new SMimeValidationConfigurationWidget(this);
    lay->addWidget(mWidget);

    connect(mWidget, &SMimeValidationConfigurationWidget::changed, this, &Kleo::Config::SMimeValidationConfigurationPage::changed);
}

void SMimeValidationConfigurationPage::load()
{
    mWidget->load();
}

void SMimeValidationConfigurationPage::save()
{
    mWidget->save();
}

void SMimeValidationConfigurationPage::defaults()
{
    mWidget->defaults();
}

#include "moc_smimevalidationconfigurationpage.cpp"
