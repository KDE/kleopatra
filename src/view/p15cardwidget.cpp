/*  view/p15cardwiget.cpp

    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2021 g10 Code GmbH
    SPDX-FileContributor: Andre Heinecke <aheinecke@g10code.com>
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include "p15cardwidget.h"

#include "cardkeysview.h"

#include "settings.h"

#include "smartcard/openpgpcard.h"
#include "smartcard/p15card.h"
#include "smartcard/readerstatus.h"

#include <QLabel>
#include <QPushButton>
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
    mStatusLabel = new QLabel{this};
    mStatusLabel->setVisible(false);
    mContentLayout->addWidget(mStatusLabel);

    mCardKeysView = new CardKeysView{this, CardKeysView::NoCreated};
    mCardKeysView->setVisible(false);
    mContentLayout->addWidget(mCardKeysView);
    connect(mCardKeysView, &CardKeysView::currentCardSlotChanged, this, &SmartCardWidget::updateActions);
}

P15CardWidget::~P15CardWidget() = default;

void P15CardWidget::searchPGPFpr(const std::string &fpr)
{
    /* Only do auto import from LDAP */
    auto conf = QGpgME::cryptoConfig();
    Q_ASSERT(conf);
    if (!Settings().alwaysSearchCardOnKeyserver() && !Kleo::keyserver().startsWith(QLatin1StringView{"ldap"})) {
        return;
    }
    mStatusLabel->setText(i18n("Searching in directory service..."));
    mStatusLabel->setVisible(true);
    qCDebug(KLEOPATRA_LOG) << "Looking for:" << fpr.c_str() << "on ldap server";
    QGpgME::KeyListJob *job = QGpgME::openpgp()->keyListJob(true);
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
    SmartCardWidget::setCard(card);

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

    /* Check if additional keys could be available */
    if (!Settings().autoLoadP15Certs()) {
        return;
    }
    mCardKeysView->setVisible(true);
    mCardKeysView->setCard(card);
}

#include "moc_p15cardwidget.cpp"
