/*
    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2018 Intevation GmbH

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include "unknownrecipientwidget.h"

#include <QFont>
#include <QHBoxLayout>
#include <QLabel>
#include <QPushButton>

#include "commands/lookupcertificatescommand.h"

#include <KLocalizedString>

using namespace Kleo;
UnknownRecipientWidget::UnknownRecipientWidget(const char *keyid, QWidget *parent)
    : QWidget(parent)
{
    auto hLay = new QHBoxLayout(this);

    auto caption = new QLabel(i18nc("Caption for an unknown key/certificate where only ID is known.", "Unknown Recipient:"));

    mKeyID = QString::fromLatin1(keyid);

    auto keyIdLabel = new QLabel(mKeyID);
    keyIdLabel->setFont(QFont(QStringLiteral("Monospace")));

    auto lookUpBtn = new QPushButton(i18nc("@action:button", "Search"));

    lookUpBtn->setIcon(QIcon::fromTheme(QStringLiteral("edit-find")));
    lookUpBtn->setToolTip(i18nc("@info:tooltip", "Search on keyserver"));
    connect(lookUpBtn, &QPushButton::clicked, this, [this, lookUpBtn]() {
        lookUpBtn->setEnabled(false);
        auto cmd = new Kleo::Commands::LookupCertificatesCommand(mKeyID, nullptr);
        connect(cmd, &Kleo::Commands::LookupCertificatesCommand::finished, this, [lookUpBtn]() {
            lookUpBtn->setEnabled(true);
        });
        cmd->setParentWidget(this->parentWidget());
        cmd->start();
    });

    hLay->addWidget(caption);
    hLay->addWidget(keyIdLabel);
    hLay->addWidget(lookUpBtn);
    hLay->addStretch(1);

    setToolTip(i18nc("@info:tooltip", "The data was encrypted to this key / certificate."));
}

QString UnknownRecipientWidget::keyID() const
{
    return mKeyID;
}

#include "moc_unknownrecipientwidget.cpp"
