/*
    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2001, 2002, 2004 Klarälvdalens Datakonsult AB

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include <config-kleopatra.h>

#include "kwatchgnupgconfig.h"

#include <KConfigGroup>
#include <KLocalization>
#include <KLocalizedString>
#include <KSharedConfig>

#include <QDialogButtonBox>
#include <QGroupBox>
#include <QLabel>
#include <QPushButton>
#include <QSpinBox>
#include <QVBoxLayout>

KWatchGnuPGConfig::KWatchGnuPGConfig(QWidget *parent)
    : QDialog(parent)
{
    setWindowTitle(i18nc("@title:window", "Configure KWatchGnuPG"));
    auto mainLayout = new QVBoxLayout(this);

    mButtonBox = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel, this);
    QPushButton *okButton = mButtonBox->button(QDialogButtonBox::Ok);
    okButton->setDefault(true);
    okButton->setShortcut(Qt::CTRL | Qt::Key_Return);
    connect(mButtonBox, &QDialogButtonBox::rejected, this, &KWatchGnuPGConfig::reject);

    auto top = new QWidget;
    mainLayout->addWidget(top);
    mainLayout->addWidget(mButtonBox);

    auto vlay = new QVBoxLayout(top);
    vlay->setContentsMargins(0, 0, 0, 0);

    auto group = new QGroupBox(i18n("Log Window"), top);
    vlay->addWidget(group);

    auto glay = new QGridLayout(group);
    glay->setColumnStretch(1, 1);

    int row = -1;

    ++row;
    mLoglenSB = new QSpinBox(group);
    mLoglenSB->setRange(0, 1000000);
    mLoglenSB->setSingleStep(100);
    KLocalization::setupSpinBoxFormatString(mLoglenSB, ki18ncp("history size spinbox suffix", "%v line", "%v lines"));
    mLoglenSB->setSpecialValueText(i18n("unlimited"));
    auto label = new QLabel(i18nc("@label:textbox", "&History size:"), group);
    label->setBuddy(mLoglenSB);
    glay->addWidget(label, row, 0);
    glay->addWidget(mLoglenSB, row, 1);
    auto button = new QPushButton(i18nc("@action:button", "Set &Unlimited"), group);
    glay->addWidget(button, row, 2);

    connect(mLoglenSB, &QSpinBox::valueChanged, this, &KWatchGnuPGConfig::slotChanged);
    connect(button, &QPushButton::clicked, this, &KWatchGnuPGConfig::slotSetHistorySizeUnlimited);

    vlay->addStretch(1);

    connect(okButton, &QPushButton::clicked, this, &KWatchGnuPGConfig::slotSave);
}

KWatchGnuPGConfig::~KWatchGnuPGConfig() = default;

void KWatchGnuPGConfig::slotSetHistorySizeUnlimited()
{
    mLoglenSB->setValue(0);
}

void KWatchGnuPGConfig::loadConfig()
{
    const KConfigGroup logWindow(KSharedConfig::openConfig(), QStringLiteral("LogWindow"));
    mLoglenSB->setValue(logWindow.readEntry("MaxLogLen", 10000));

    mButtonBox->button(QDialogButtonBox::Ok)->setEnabled(false);
}

void KWatchGnuPGConfig::saveConfig()
{
    KConfigGroup logWindow(KSharedConfig::openConfig(), QStringLiteral("LogWindow"));
    logWindow.writeEntry("MaxLogLen", mLoglenSB->value());

    KSharedConfig::openConfig()->sync();

    mButtonBox->button(QDialogButtonBox::Ok)->setEnabled(false);
}

void KWatchGnuPGConfig::slotChanged()
{
    mButtonBox->button(QDialogButtonBox::Ok)->setEnabled(true);
}

void KWatchGnuPGConfig::slotSave()
{
    saveConfig();
    Q_EMIT reconfigure();
    accept();
}

#include "moc_kwatchgnupgconfig.cpp"
