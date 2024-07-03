/*  view/p15cardwiget.cpp

    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2021 g10 Code GmbH
    SPDX-FileContributor: Andre Heinecke <aheinecke@g10code.com>
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include "p15cardwidget.h"

#include "cardkeysview.h"
#include "openpgpkeycardwidget.h"

#include "settings.h"

#include "smartcard/openpgpcard.h"
#include "smartcard/p15card.h"
#include "smartcard/readerstatus.h"

#include <QGridLayout>
#include <QLabel>
#include <QPushButton>
#include <QScrollArea>
#include <QStringList>
#include <QVBoxLayout>

#include <KLocalizedString>
#include <KSeparator>

#include <Libkleo/Compat>
#include <Libkleo/Formatting>
#include <Libkleo/GnuPG>
#include <Libkleo/KeyCache>

#include <QGpgME/CryptoConfig>
#include <QGpgME/ImportFromKeyserverJob>
#include <QGpgME/KeyListJob>
#include <QGpgME/Protocol>

#include <gpgme++/importresult.h>
#include <gpgme++/keylistresult.h>

#include "kleopatra_debug.h"

using namespace Kleo;
using namespace Kleo::SmartCard;

P15CardWidget::P15CardWidget(QWidget *parent)
    : SmartCardWidget{parent}
{
    // Set up the scroll area
    auto myLayout = new QVBoxLayout(this);
    myLayout->setContentsMargins(0, 0, 0, 0);

    auto area = new QScrollArea;
    area->setFocusPolicy(Qt::NoFocus);
    area->setFrameShape(QFrame::NoFrame);
    area->setWidgetResizable(true);
    myLayout->addWidget(area);

    auto areaWidget = new QWidget;
    area->setWidget(areaWidget);

    auto areaVLay = new QVBoxLayout(areaWidget);

    auto cardInfoGrid = new QGridLayout;
    {
        int row = 0;

        // Version and Serialnumber
        mVersionLabel = new QLabel{this};
        mVersionLabel->setTextInteractionFlags(Qt::TextBrowserInteraction | Qt::TextSelectableByKeyboard);
        cardInfoGrid->addWidget(mVersionLabel, row++, 0, 1, 2);

        cardInfoGrid->addWidget(new QLabel(i18n("Serial number:")), row, 0);
        mSerialNumberLabel = new QLabel{this};
        mSerialNumberLabel->setTextInteractionFlags(Qt::TextBrowserInteraction | Qt::TextSelectableByKeyboard);
        cardInfoGrid->addWidget(mSerialNumberLabel, row++, 1);

        cardInfoGrid->setColumnStretch(cardInfoGrid->columnCount(), 1);
    }
    areaVLay->addLayout(cardInfoGrid);
    mStatusLabel = new QLabel{this};
    mStatusLabel->setVisible(false);
    areaVLay->addWidget(mStatusLabel);

    areaVLay->addWidget(new KSeparator(Qt::Horizontal));

    mOpenPGPKeysSection = new QWidget{this};
    {
        auto l = new QVBoxLayout{mOpenPGPKeysSection};
        l->setContentsMargins(0, 0, 0, 0);
        l->addWidget(new QLabel(QStringLiteral("<b>%1</b>").arg(i18n("OpenPGP keys:"))));
        mOpenPGPKeysWidget = new OpenPGPKeyCardWidget{this};
        mOpenPGPKeysWidget->setAllowedActions(OpenPGPKeyCardWidget::NoAction);
        l->addWidget(mOpenPGPKeysWidget);
        l->addWidget(new KSeparator(Qt::Horizontal));
    }
    mOpenPGPKeysSection->setVisible(false);
    areaVLay->addWidget(mOpenPGPKeysSection);

    mCardKeysView = new CardKeysView{this};
    mCardKeysView->setVisible(false);
    areaVLay->addWidget(mCardKeysView);

    areaVLay->addStretch(1);
}

P15CardWidget::~P15CardWidget() = default;

void P15CardWidget::searchPGPFpr(const std::string &fpr)
{
    /* Only do auto import from LDAP */
    auto conf = QGpgME::cryptoConfig();
    Q_ASSERT(conf);
    if (!Settings().alwaysSearchCardOnKeyserver() && !Kleo::keyserver().startsWith(QLatin1String{"ldap"})) {
        return;
    }
    mStatusLabel->setText(i18n("Searching in directory service..."));
    mStatusLabel->setVisible(true);
    qCDebug(KLEOPATRA_LOG) << "Looking for:" << fpr.c_str() << "on ldap server";
    QGpgME::KeyListJob *job = QGpgME::openpgp()->keyListJob(true);
    connect(KeyCache::instance().get(), &KeyCache::keysMayHaveChanged, this, [this, fpr]() {
        qCDebug(KLEOPATRA_LOG) << "Updating key info after changes";
        ReaderStatus::mutableInstance()->updateStatus();
        mOpenPGPKeysWidget->update(nullptr);
    });
    connect(job, &QGpgME::KeyListJob::result, job, [this](GpgME::KeyListResult, std::vector<GpgME::Key> keys, QString, GpgME::Error) {
        if (keys.size() == 1) {
            auto importJob = QGpgME::openpgp()->importFromKeyserverJob();
            qCDebug(KLEOPATRA_LOG) << "Importing: " << keys[0].primaryFingerprint();
            connect(importJob, &QGpgME::ImportFromKeyserverJob::result, importJob, [this](GpgME::ImportResult, QString, GpgME::Error) {
                qCDebug(KLEOPATRA_LOG) << "import job done";
                mStatusLabel->setText(i18n("Automatic import finished."));
            });
            importJob->start(keys);
        } else if (keys.size() > 1) {
            qCDebug(KLEOPATRA_LOG) << "Multiple keys found on server";
            mStatusLabel->setText(i18n("Error multiple keys found on server."));
        } else {
            qCDebug(KLEOPATRA_LOG) << "No key found";
            mStatusLabel->setText(i18n("Key not found in directory service."));
        }
    });
    job->start(QStringList() << QString::fromStdString(fpr));
}

void P15CardWidget::setCard(const P15Card *card)
{
    mSerialNumber = card->serialNumber();
    mVersionLabel->setText(i18nc("%1 is a smartcard manufacturer", "%1 PKCS#15 card", QString::fromStdString(card->manufacturer())));
    mSerialNumberLabel->setText(card->displaySerialNumber());
    mSerialNumberLabel->setToolTip(QString::fromStdString(card->serialNumber()));

    const auto sigInfo = card->keyInfo(card->signingKeyRef());
    if (!sigInfo.grip.empty()) {
        const auto key = KeyCache::instance()->findSubkeyByKeyGrip(sigInfo.grip, GpgME::OpenPGP).parent();
        if (key.isNull()) {
            qCDebug(KLEOPATRA_LOG) << "Failed to find key for grip:" << sigInfo.grip.c_str();
            const auto pgpSigFpr = card->keyFingerprint(OpenPGPCard::pgpSigKeyRef());
            if (!pgpSigFpr.empty()) {
                qCDebug(KLEOPATRA_LOG) << "Should be pgp key:" << pgpSigFpr.c_str();
                searchPGPFpr(pgpSigFpr);
            }
        } else {
            mStatusLabel->setVisible(false);
        }
    }

    const bool cardHasOpenPGPKeys = (!card->keyFingerprint(OpenPGPCard::pgpSigKeyRef()).empty() //
                                     || !card->keyFingerprint(OpenPGPCard::pgpEncKeyRef()).empty());
    mOpenPGPKeysSection->setVisible(cardHasOpenPGPKeys);
    if (cardHasOpenPGPKeys) {
        mOpenPGPKeysWidget->update(card);
    }

    /* Check if additional keys could be available */
    if (!Settings().autoLoadP15Certs()) {
        return;
    }
    mCardKeysView->setVisible(true);
    mCardKeysView->setCard(card);
}
