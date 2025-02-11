/* -*- mode: c++; c-basic-offset:4 -*-
    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2008 Klarälvdalens Datakonsult AB

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include "gnupgsystemconfigurationpage.h"
#include <config-kleopatra.h>

#include <Libkleo/CryptoConfigModule>
#include <QGpgME/CryptoConfig>
#include <QGpgME/Protocol>

#include <QVBoxLayout>

using namespace Kleo::Config;

GnuPGSystemConfigurationPage::GnuPGSystemConfigurationPage(QWidget *parent)
    : KleoConfigModule(parent)
{
    auto lay = new QVBoxLayout(this);
    lay->setContentsMargins(0, 0, 0, 0);

    QGpgME::CryptoConfig *const config = QGpgME::cryptoConfig();

    mWidget = new CryptoConfigModule(config, this);
    lay->addWidget(mWidget);

    connect(mWidget, &CryptoConfigModule::changed, this, &Kleo::Config::GnuPGSystemConfigurationPage::changed);
}

GnuPGSystemConfigurationPage::~GnuPGSystemConfigurationPage()
{
    // ### correct here?
    if (QGpgME::CryptoConfig *const config = QGpgME::cryptoConfig()) {
        config->clear();
    }
}

void GnuPGSystemConfigurationPage::load()
{
    mWidget->reset();
}

void GnuPGSystemConfigurationPage::save()
{
    mWidget->save();
}

void GnuPGSystemConfigurationPage::defaults()
{
    mWidget->defaults();
}

#include "moc_gnupgsystemconfigurationpage.cpp"
