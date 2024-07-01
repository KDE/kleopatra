/*  view/cardkeysview.cpp

    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2024 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include "cardkeysview.h"

#include "keytreeview.h"

#include <kleopatra_debug.h>

#include <commands/detailscommand.h>
#include <smartcard/card.h>
#include <smartcard/readerstatus.h>
#include <utils/qt-cxx20-compat.h>
#include <view/progressoverlay.h>

#include <Libkleo/Debug>
#include <Libkleo/KeyCache>
#include <Libkleo/KeyHelpers>
#include <Libkleo/KeyListModel>

#include <KConfigGroup>
#include <KLocalizedString>
#include <KSharedConfig>

#include <QGpgME/KeyListJob>
#include <QGpgME/Protocol>

#include <QLabel>
#include <QVBoxLayout>

#include <gpgme++/context.h>
#include <gpgme++/key.h>
#include <gpgme++/keylistresult.h>

#include <algorithm>

using namespace Kleo;
using namespace Kleo::SmartCard;
using namespace Kleo::Commands;

CardKeysView::CardKeysView(QWidget *parent)
    : QWidget{parent}
    , mTreeView{new KeyTreeView{this}}
{
    auto mainLayout = new QVBoxLayout{this};
    mainLayout->setContentsMargins({});

    auto label = new QLabel{QLatin1String{"<b>"} + i18nc("@label:listbox", "Certificates:") + QLatin1String{"</b>"}, this};
    label->setBuddy(mTreeView);
    mainLayout->addWidget(label, 0, Qt::AlignLeft);

    // The certificate view
    mTreeView->setHierarchicalModel(AbstractKeyListModel::createHierarchicalKeyListModel(mTreeView));
    mTreeView->setHierarchicalView(true);

    connect(mTreeView->view(), &QAbstractItemView::doubleClicked, this, [this](const QModelIndex &idx) {
        const auto klm = dynamic_cast<KeyListModelInterface *>(mTreeView->view()->model());
        if (!klm) {
            qCDebug(KLEOPATRA_LOG) << "Unhandled Model: " << mTreeView->view()->model()->metaObject()->className();
            return;
        }
        auto cmd = new DetailsCommand(klm->key(idx));
        cmd->setParentWidget(this);
        cmd->start();
    });
    mainLayout->addWidget(mTreeView);

    mTreeViewOverlay = new ProgressOverlay{mTreeView, this};
    mTreeViewOverlay->hide();

    mainLayout->addStretch(1);

    QMetaObject::invokeMethod(
        this,
        [this]() {
            // delay restoring the column layout until the widget tree has been set up
            const KConfigGroup configGroup{KSharedConfig::openConfig(), "CardKeysView"};
            mTreeView->restoreLayout(configGroup);
        },
        Qt::QueuedConnection);

    connect(KeyCache::instance().get(), &KeyCache::keysMayHaveChanged, this, &CardKeysView::loadCertificates);
}

CardKeysView::~CardKeysView() = default;

void CardKeysView::setCard(const Card *card)
{
    mSerialNumber = card->serialNumber();
    mAppName = card->appName();

    loadCertificates();
    if (mCertificates.size() != card->keyInfos().size()) {
        // the card contains keys we don't know; try to learn them from the card
        learnCard();
    }
}

void CardKeysView::loadCertificates()
{
    qCDebug(KLEOPATRA_LOG) << __func__;
    if (mSerialNumber.empty()) {
        // ignore KeyCache::keysMayHaveChanged signal until the card has been set
        return;
    }

    const auto card = ReaderStatus::instance()->getCard(mSerialNumber, mAppName);
    if (!card) {
        qCDebug(KLEOPATRA_LOG) << "Failed to find the" << mAppName << "smart card with the serial number" << mSerialNumber;
        return;
    }

    const auto cardKeyInfos = card->keyInfos();
    mCertificates.clear();
    mCertificates.reserve(cardKeyInfos.size());

    // try to get the certificates from the key cache
    for (const auto &cardKeyInfo : cardKeyInfos) {
        const auto certificate = KeyCache::instance()->findSubkeyByKeyGrip(cardKeyInfo.grip, GpgME::CMS).parent();
        if (!certificate.isNull()) {
            qCDebug(KLEOPATRA_LOG) << __func__ << "Found certificate for card key" << cardKeyInfo.grip << "in cache:" << certificate;
            mCertificates.push_back(certificate);
        } else {
            qCDebug(KLEOPATRA_LOG) << __func__ << "Did not find certificate for card key" << cardKeyInfo.grip << "in cache";
        }
    }
    mTreeView->setKeys(mCertificates);

    ensureCertificatesAreValidated();
}

void CardKeysView::ensureCertificatesAreValidated()
{
    if (mCertificates.empty()) {
        return;
    }

    std::vector<GpgME::Key> certificatesToValidate;
    certificatesToValidate.reserve(mCertificates.size());
    std::ranges::copy_if(mCertificates, std::back_inserter(certificatesToValidate), [this](const auto &cert) {
        // don't bother validating certificates that have expired or are otherwise invalid
        return !cert.isBad() && !mValidatedCertificates.contains(cert);
    });
    if (!certificatesToValidate.empty()) {
        startCertificateValidation(certificatesToValidate);
        mValidatedCertificates.insert(certificatesToValidate.cbegin(), certificatesToValidate.cend());
    }
}

void CardKeysView::startCertificateValidation(const std::vector<GpgME::Key> &certificates)
{
    qCDebug(KLEOPATRA_LOG) << __func__ << "Validating certificates" << certificates;
    auto job = std::unique_ptr<QGpgME::KeyListJob>{QGpgME::smime()->keyListJob(false, true, true)};
    auto ctx = QGpgME::Job::context(job.get());
    ctx->addKeyListMode(GpgME::WithSecret);

    connect(job.get(), &QGpgME::KeyListJob::result, this, &CardKeysView::certificateValidationDone);

    job->start(Kleo::getFingerprints(certificates));
    job.release();
}

void CardKeysView::certificateValidationDone(const GpgME::KeyListResult &result, const std::vector<GpgME::Key> &validatedCertificates)
{
    qCDebug(KLEOPATRA_LOG) << __func__ << "certificates:" << validatedCertificates;
    if (result.error()) {
        qCDebug(KLEOPATRA_LOG) << __func__ << "Validating certificates failed:" << result.error();
        return;
    }
    // replace the current certificates with the validated certificates
    for (const auto &validatedCert : validatedCertificates) {
        const auto fpr = validatedCert.primaryFingerprint();
        const auto it = std::find_if(mCertificates.begin(), mCertificates.end(), [fpr](const auto &cert) {
            return !qstrcmp(fpr, cert.primaryFingerprint());
        });
        if (it != mCertificates.end()) {
            *it = validatedCert;
        } else {
            qCDebug(KLEOPATRA_LOG) << __func__ << "Didn't find validated certificate in certificate list:" << validatedCert;
        }
    }
    mTreeView->setKeys(mCertificates);
}

void CardKeysView::learnCard()
{
    qCDebug(KLEOPATRA_LOG) << __func__;
    mTreeViewOverlay->setText(i18nc("@info", "Reading certificates from smart card ..."));
    mTreeViewOverlay->showOverlay();
    ReaderStatus::mutableInstance()->learnCards(GpgME::CMS);
    connect(ReaderStatus::instance(), &ReaderStatus::cardsLearned, this, [this]() {
        qCDebug(KLEOPATRA_LOG) << "ReaderStatus::cardsLearned";
        mTreeViewOverlay->hideOverlay();
    });
}

#include "moc_cardkeysview.cpp"
