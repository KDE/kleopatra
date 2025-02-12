/*
    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2008 Klarälvdalens Datakonsult AB
    SPDX-FileCopyrightText: 2019 g10code GmbH

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include <config-kleopatra.h>

#include "certifycertificatecommand.h"
#include "newopenpgpcertificatecommand.h"

#include "command_p.h"

#include "dialogs/certifycertificatedialog.h"
#include "exportopenpgpcertstoservercommand.h"

#include <Libkleo/Algorithm>
#include <Libkleo/Compat>
#include <Libkleo/Formatting>
#include <Libkleo/KeyCache>
#include <Libkleo/KeyHelpers>

#include <QGpgME/Protocol>
#include <QGpgME/SignKeyJob>

#include <QDate>
#include <QEventLoop>

#include <gpgme++/key.h>

#include "kleopatra_debug.h"
#include <KLocalizedString>

using namespace Kleo;
using namespace Kleo::Commands;
using namespace GpgME;
using namespace QGpgME;

class CertifyCertificateCommand::Private : public Command::Private
{
    friend class ::Kleo::Commands::CertifyCertificateCommand;
    CertifyCertificateCommand *q_func() const
    {
        return static_cast<CertifyCertificateCommand *>(q);
    }

public:
    explicit Private(CertifyCertificateCommand *qq, KeyListController *c);
    ~Private() override;

    void init();

private:
    void slotDialogRejected();
    void slotResult(const Error &err);
    void slotCertificationPrepared();

private:
    void ensureDialogCreated();
    void createJob();

private:
    GpgME::Key target;
    std::vector<UserID> uids;
    QPointer<CertifyCertificateDialog> dialog;
    QPointer<QGpgME::SignKeyJob> job;
};

CertifyCertificateCommand::Private *CertifyCertificateCommand::d_func()
{
    return static_cast<Private *>(d.get());
}
const CertifyCertificateCommand::Private *CertifyCertificateCommand::d_func() const
{
    return static_cast<const Private *>(d.get());
}

#define d d_func()
#define q q_func()

CertifyCertificateCommand::Private::Private(CertifyCertificateCommand *qq, KeyListController *c)
    : Command::Private(qq, c)
    , uids()
    , dialog()
    , job()
{
}

CertifyCertificateCommand::Private::~Private()
{
    qCDebug(KLEOPATRA_LOG);
    if (dialog) {
        delete dialog;
        dialog = nullptr;
    }
}

CertifyCertificateCommand::CertifyCertificateCommand(KeyListController *c)
    : Command(new Private(this, c))
{
    d->init();
}

CertifyCertificateCommand::CertifyCertificateCommand(QAbstractItemView *v, KeyListController *c)
    : Command(v, new Private(this, c))
{
    d->init();
}

CertifyCertificateCommand::CertifyCertificateCommand(const GpgME::Key &key)
    : Command(key, new Private(this, nullptr))
{
    d->init();
}

CertifyCertificateCommand::CertifyCertificateCommand(const GpgME::UserID &uid)
    : Command(uid.parent(), new Private(this, nullptr))
{
    std::vector<UserID>(1, uid).swap(d->uids);
    d->init();
}

CertifyCertificateCommand::CertifyCertificateCommand(const std::vector<GpgME::UserID> &uids)
    : Command(uids.empty() ? Key() : uids.front().parent(), new Private(this, nullptr))
{
    d->uids = uids;
    d->init();
}

void CertifyCertificateCommand::Private::init()
{
}

CertifyCertificateCommand::~CertifyCertificateCommand()
{
    qCDebug(KLEOPATRA_LOG);
}

void CertifyCertificateCommand::doStart()
{
    const std::vector<Key> keys = d->keys();
    if (keys.size() != 1 || keys.front().protocol() != GpgME::OpenPGP) {
        d->finished();
        return;
    }
    // hold on to the key to certify to avoid invalidation during refreshes of the key cache
    d->target = keys.front();

    if (d->target.isExpired() || d->target.isRevoked()) {
        const auto title = d->target.isRevoked() ? i18nc("@title:window", "Key is Revoked") : i18nc("@title:window", "Key is Expired");
        const auto message = d->target.isRevoked() //
            ? i18nc("@info", "This key has been revoked. You cannot certify it.")
            : i18nc("@info", "This key has expired. You cannot certify it.");
        d->information(message, title);
        d->finished();
        return;
    }

    auto findAnyGoodKey = []() {
        const std::vector<Key> secKeys = KeyCache::instance()->secretKeys();
        return std::any_of(secKeys.cbegin(), secKeys.cend(), [](const Key &secKey) {
            return Kleo::keyHasCertify(secKey) && secKey.protocol() == OpenPGP && !secKey.isRevoked() && !secKey.isExpired() && !secKey.isInvalid();
        });
    };

    if (!findAnyGoodKey()) {
        auto sel =
            KMessageBox::questionTwoActions(d->parentWidgetOrView(),
                                            xi18nc("@info", "To certify other certificates, you first need to create an OpenPGP certificate for yourself.")
                                                + QStringLiteral("<br><br>") + i18n("Do you wish to create one now?"),
                                            i18nc("@title:window", "Certification Not Possible"),
                                            KGuiItem(i18nc("@action:button", "Create")),
                                            KStandardGuiItem::cancel());
        if (sel == KMessageBox::ButtonCode::PrimaryAction) {
            QEventLoop loop;
            auto cmd = new NewOpenPGPCertificateCommand;
            cmd->setParentWidget(d->parentWidgetOrView());
            connect(cmd, &Command::finished, &loop, &QEventLoop::quit);
            QMetaObject::invokeMethod(cmd, &NewOpenPGPCertificateCommand::start, Qt::QueuedConnection);
            loop.exec();
        } else {
            d->canceled();
            return;
        }

        // Check again for secret keys
        if (!findAnyGoodKey()) {
            qCDebug(KLEOPATRA_LOG) << "Sec Keys still empty after keygen.";
            d->canceled();
            return;
        }
    }

    const char *primary = keys.front().primaryFingerprint();
    const bool anyMismatch = std::any_of(d->uids.cbegin(), d->uids.cend(), [primary](const UserID &uid) {
        return qstricmp(uid.parent().primaryFingerprint(), primary) != 0;
    });
    if (anyMismatch) {
        qCWarning(KLEOPATRA_LOG) << "User ID <-> Key mismatch!";
        d->finished();
        return;
    }

    d->ensureDialogCreated();
    Q_ASSERT(d->dialog);

    d->dialog->setCertificateToCertify(d->target, d->uids);
    d->dialog->show();
}

void CertifyCertificateCommand::Private::slotDialogRejected()
{
    canceled();
}

void CertifyCertificateCommand::Private::slotResult(const Error &err)
{
    if (err.isCanceled()) {
        // do nothing
    } else if (err) {
        error(i18n("<p>An error occurred while trying to certify<br/><br/>"
                   "<b>%1</b>:</p><p>\t%2</p>",
                   Formatting::formatForComboBox(target),
                   Formatting::errorAsString(err)),
              i18n("Certification Error"));
    } else if (dialog && dialog->exportableCertificationSelected() && dialog->sendToServer()) {
        auto const cmd = new ExportOpenPGPCertsToServerCommand(target);
        cmd->start();
    } else {
        information(i18n("Certification successful."), i18n("Certification Succeeded"));
    }

    finished();
}

void CertifyCertificateCommand::Private::slotCertificationPrepared()
{
    Q_ASSERT(dialog);

    const auto selectedUserIds = dialog->selectedUserIDs();
    std::vector<unsigned int> userIdIndexes;
    userIdIndexes.reserve(selectedUserIds.size());
    for (unsigned int i = 0, numUserIds = target.numUserIDs(); i < numUserIds; ++i) {
        const auto userId = target.userID(i);
        const bool userIdIsSelected = std::ranges::any_of(selectedUserIds, [userId](const auto &uid) {
            return Kleo::userIDsAreEqual(userId, uid);
        });
        if (userIdIsSelected) {
            userIdIndexes.push_back(i);
        }
    }

    createJob();
    Q_ASSERT(job);
    job->setExportable(dialog->exportableCertificationSelected());
    job->setUserIDsToSign(userIdIndexes);
    job->setSigningKey(dialog->selectedSecretKey());
    if (!dialog->tags().isEmpty()) {
        // do not set an empty remark to avoid an empty signature notation (GnuPG bug T5142)
        job->setRemark(dialog->tags());
    }
    job->setDupeOk(true);
    if (dialog->trustSignatureSelected() && !dialog->trustSignatureDomain().isEmpty()) {
        // always create level 1 trust signatures with complete trust
        job->setTrustSignature(TrustSignatureTrust::Complete, 1, dialog->trustSignatureDomain());
    }
    if (!dialog->expirationDate().isNull()) {
        job->setExpirationDate(dialog->expirationDate());
    }

    if (const Error err = job->start(target)) {
        slotResult(err);
    }
}

void CertifyCertificateCommand::doCancel()
{
    qCDebug(KLEOPATRA_LOG);
    if (d->job) {
        d->job->slotCancel();
    }
}

void CertifyCertificateCommand::Private::ensureDialogCreated()
{
    if (dialog) {
        return;
    }

    dialog = new CertifyCertificateDialog;
    applyWindowID(dialog);

    connect(dialog, &QDialog::rejected, q, [this]() {
        slotDialogRejected();
    });
    connect(dialog, &QDialog::accepted, q, [this]() {
        slotCertificationPrepared();
    });
}

void CertifyCertificateCommand::Private::createJob()
{
    Q_ASSERT(!job);

    Q_ASSERT(target.protocol() == OpenPGP);
    const auto backend = QGpgME::openpgp();
    if (!backend) {
        return;
    }

    SignKeyJob *const j = backend->signKeyJob();
    if (!j) {
        return;
    }

    connect(j, &QGpgME::Job::jobProgress, q, &Command::progress);
    connect(j, &SignKeyJob::result, q, [this](const GpgME::Error &result) {
        slotResult(result);
    });

    job = j;
}

#undef d
#undef q

#include "moc_certifycertificatecommand.cpp"
