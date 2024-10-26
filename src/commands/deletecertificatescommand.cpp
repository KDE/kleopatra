/* -*- mode: c++; c-basic-offset:4 -*-
    deleteCertificatescommand.cpp

    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2007 Klarälvdalens Datakonsult AB

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include <config-kleopatra.h>

#include "deletecertificatescommand.h"

#include "command_p.h"

#include <dialogs/deletecertificatesdialog.h>

#include <Libkleo/Formatting>
#include <Libkleo/KeyCache>
#include <Libkleo/Predicates>

#include <Libkleo/Stl_Util>

#include <QGpgME/DeleteJob>
#include <QGpgME/MultiDeleteJob>
#include <QGpgME/Protocol>

#include <gpgme++/key.h>

#include <KLocalizedString>

#include <QAbstractItemView>
#include <QPointer>

#include <KLazyLocalizedString>
#include <algorithm>
#include <vector>
using namespace GpgME;
using namespace Kleo;
using namespace Kleo::Dialogs;
using namespace QGpgME;

class DeleteCertificatesCommand::Private : public Command::Private
{
    friend class ::Kleo::DeleteCertificatesCommand;
    DeleteCertificatesCommand *q_func() const
    {
        return static_cast<DeleteCertificatesCommand *>(q);
    }

public:
    explicit Private(DeleteCertificatesCommand *qq, KeyListController *c);
    ~Private() override;

    void startDeleteJob(GpgME::Protocol protocol);

    void cancelJobs();
    void pgpDeleteResult(const GpgME::Error &);
    void cmsDeleteResult(const GpgME::Error &);
    void showErrorsAndFinish();

    bool canDelete(GpgME::Protocol proto) const
    {
        if (const auto cbp = (proto == GpgME::OpenPGP ? QGpgME::openpgp() : QGpgME::smime()))
            if (DeleteJob *const job = cbp->deleteJob()) {
                job->slotCancel();
                return true;
            }
        return false;
    }

    void ensureDialogCreated()
    {
        if (dialog) {
            return;
        }
        dialog = new DeleteCertificatesDialog;
        applyWindowID(dialog);
        dialog->setAttribute(Qt::WA_DeleteOnClose);
        dialog->setWindowTitle(i18nc("@title:window", "Delete Certificates"));
        connect(dialog, &QDialog::accepted, q_func(), [this]() {
            slotDialogAccepted();
        });
        connect(dialog, &QDialog::rejected, q_func(), [this]() {
            slotDialogRejected();
        });
    }
    void ensureDialogShown()
    {
        if (dialog) {
            dialog->show();
        }
    }

    void slotDialogAccepted();
    void slotDialogRejected()
    {
        canceled();
    }

private:
    QPointer<DeleteCertificatesDialog> dialog;
    QPointer<MultiDeleteJob> cmsJob, pgpJob;
    GpgME::Error cmsError, pgpError;
    std::vector<Key> cmsKeys, pgpKeys;
};

DeleteCertificatesCommand::Private *DeleteCertificatesCommand::d_func()
{
    return static_cast<Private *>(d.get());
}
const DeleteCertificatesCommand::Private *DeleteCertificatesCommand::d_func() const
{
    return static_cast<const Private *>(d.get());
}

#define d d_func()
#define q q_func()

DeleteCertificatesCommand::Private::Private(DeleteCertificatesCommand *qq, KeyListController *c)
    : Command::Private(qq, c)
{
}

DeleteCertificatesCommand::Private::~Private()
{
}

DeleteCertificatesCommand::DeleteCertificatesCommand(KeyListController *p)
    : Command(new Private(this, p))
{
}

DeleteCertificatesCommand::DeleteCertificatesCommand(QAbstractItemView *v, KeyListController *p)
    : Command(v, new Private(this, p))
{
}

DeleteCertificatesCommand::~DeleteCertificatesCommand()
{
}

namespace
{

enum Action {
    Nothing = 0,
    Failure = 1,
    ClearCMS = 2,
    ClearPGP = 4
};

// const unsigned int errorCase =
//    openpgp.empty() << 3U | d->canDelete( OpenPGP ) << 2U |
//        cms.empty() << 1U |     d->canDelete( CMS ) << 0U ;

static const struct {
    const KLazyLocalizedString text;
    Action actions;
} deletionErrorCases[16] = {
    // if havePGP
    //   if cantPGP
    //     if haveCMS
    {kli18n("Neither the OpenPGP nor the CMS "
            "backends support certificate deletion.\n"
            "Check your installation."),
     Failure}, // cantCMS
    {kli18n("The OpenPGP backend does not support "
            "certificate deletion.\n"
            "Check your installation.\n"
            "Only the selected CMS certificates "
            "will be deleted."),
     ClearPGP}, // canCMS
    //     if !haveCMS
    {kli18n("The OpenPGP backend does not support "
            "certificate deletion.\n"
            "Check your installation."),
     Failure},
    {kli18n("The OpenPGP backend does not support "
            "certificate deletion.\n"
            "Check your installation."),
     Failure},
    //   if canPGP
    //      if haveCMS
    {kli18n("The CMS backend does not support "
            "certificate deletion.\n"
            "Check your installation.\n"
            "Only the selected OpenPGP certificates "
            "will be deleted."),
     ClearCMS}, //                        cantCMS
    {KLazyLocalizedString(), Nothing}, // canCMS
    //      if !haveCMS
    {KLazyLocalizedString(), Nothing}, // cantCMS
    {KLazyLocalizedString(), Nothing}, // canCMS
    // if !havePGP
    //   if cantPGP
    //     if haveCMS
    {kli18n("The CMS backend does not support "
            "certificate deletion.\n"
            "Check your installation."),
     Failure}, //                         cantCMS
    {KLazyLocalizedString(), Nothing}, // canCMS
    //     if !haveCMS
    {KLazyLocalizedString(), Nothing}, // cantCMS
    {KLazyLocalizedString(), Nothing}, // canCMS
    //  if canPGP
    //     if haveCMS
    {kli18n("The CMS backend does not support "
            "certificate deletion.\n"
            "Check your installation."),
     Failure}, //                         cantCMS
    {KLazyLocalizedString(), Nothing}, // canCMS
    //     if !haveCMS
    {KLazyLocalizedString(), Nothing}, // cantCMS
    {KLazyLocalizedString(), Nothing}, // canCMS
};
} // anon namespace

void DeleteCertificatesCommand::doStart()
{
    std::vector<Key> selected = d->keys();
    if (selected.empty()) {
        d->finished();
        return;
    }

    std::sort(selected.begin(), selected.end(), _detail::ByFingerprint<std::less>());

    // Calculate the closure of the selected keys (those that need to
    // be deleted with them, though not selected themselves):

    std::vector<Key> toBeDeleted = KeyCache::instance()->findSubjects(selected);
    std::sort(toBeDeleted.begin(), toBeDeleted.end(), _detail::ByFingerprint<std::less>());

    std::vector<Key> unselected;
    unselected.reserve(toBeDeleted.size());
    std::set_difference(toBeDeleted.begin(),
                        toBeDeleted.end(),
                        selected.begin(),
                        selected.end(),
                        std::back_inserter(unselected),
                        _detail::ByFingerprint<std::less>());

    d->ensureDialogCreated();

    d->dialog->setSelectedKeys(selected);
    d->dialog->setUnselectedKeys(unselected);

    d->ensureDialogShown();
}

void DeleteCertificatesCommand::Private::slotDialogAccepted()
{
    std::vector<Key> keys = dialog->keys();
    Q_ASSERT(!keys.empty());

    auto pgpBegin = keys.begin();
    auto pgpEnd = std::stable_partition(pgpBegin, keys.end(), [](const GpgME::Key &key) {
        return key.protocol() != GpgME::CMS;
    });
    auto cmsBegin = pgpEnd;
    auto cmsEnd = keys.end();

    std::vector<Key> openpgp(pgpBegin, pgpEnd);
    std::vector<Key> cms(cmsBegin, cmsEnd);

    const unsigned int errorCase = //
        openpgp.empty() << 3U //
        | canDelete(OpenPGP) << 2U //
        | cms.empty() << 1U //
        | canDelete(CMS) << 0U;

    if (const unsigned int actions = deletionErrorCases[errorCase].actions) {
        information(KLocalizedString(deletionErrorCases[errorCase].text).toString(),
                    (actions & Failure) ? i18n("Certificate Deletion Failed") : i18n("Certificate Deletion Problem"));

        if (actions & ClearCMS) {
            cms.clear();
        }
        if (actions & ClearPGP) {
            openpgp.clear();
        }
        if (actions & Failure) {
            canceled();
            return;
        }
    }

    Q_ASSERT(!openpgp.empty() || !cms.empty());

    pgpKeys.swap(openpgp);
    cmsKeys.swap(cms);

    if (!pgpKeys.empty()) {
        startDeleteJob(GpgME::OpenPGP);
    }
    if (!cmsKeys.empty()) {
        startDeleteJob(GpgME::CMS);
    }

    if ((pgpKeys.empty() || pgpError.code()) && (cmsKeys.empty() || cmsError.code())) {
        showErrorsAndFinish();
    }
}

void DeleteCertificatesCommand::Private::startDeleteJob(GpgME::Protocol protocol)
{
    Q_ASSERT(protocol != GpgME::UnknownProtocol);

    const std::vector<Key> &keys = protocol == CMS ? cmsKeys : pgpKeys;

    const auto backend = (protocol == GpgME::OpenPGP) ? QGpgME::openpgp() : QGpgME::smime();
    Q_ASSERT(backend);

    std::unique_ptr<MultiDeleteJob> job(new MultiDeleteJob(backend));

    connect(job.get(), &QGpgME::MultiDeleteJob::result, q_func(), [this, protocol](const GpgME::Error &result) {
        if (protocol == CMS) {
            cmsDeleteResult(result);
        } else {
            pgpDeleteResult(result);
        }
    });

    connect(job.get(), &QGpgME::Job::jobProgress, q, &Command::progress);

    if (const Error err = job->start(keys, true /*allowSecretKeyDeletion*/)) {
        (protocol == CMS ? cmsError : pgpError) = err;
    } else {
        (protocol == CMS ? cmsJob : pgpJob) = job.release();
    }
}

void DeleteCertificatesCommand::Private::showErrorsAndFinish()
{
    Q_ASSERT(!pgpJob);
    Q_ASSERT(!cmsJob);

    if (pgpError || cmsError) {
        QString pgpErrorString;
        if (pgpError) {
            pgpErrorString = i18n("OpenPGP backend: %1", Formatting::errorAsString(pgpError));
        }
        QString cmsErrorString;
        if (cmsError) {
            cmsErrorString = i18n("CMS backend: %1", Formatting::errorAsString(cmsError));
        }

        const QString msg = i18n(
            "<qt><p>An error occurred while trying to delete "
            "the certificate:</p>"
            "<p><b>%1</b></p></qt>",
            pgpError ? cmsError ? pgpErrorString + QLatin1StringView("</br>") + cmsErrorString : pgpErrorString : cmsErrorString);
        error(msg, i18n("Certificate Deletion Failed"));
    } else if (!pgpError.isCanceled() && !cmsError.isCanceled()) {
        std::vector<Key> keys = pgpKeys;
        keys.insert(keys.end(), cmsKeys.begin(), cmsKeys.end());
        KeyCache::mutableInstance()->remove(keys);
    }

    finished();
}

void DeleteCertificatesCommand::doCancel()
{
    d->cancelJobs();
}

void DeleteCertificatesCommand::Private::pgpDeleteResult(const Error &err)
{
    pgpError = err;
    pgpJob = nullptr;
    if (!cmsJob) {
        showErrorsAndFinish();
    }
}

void DeleteCertificatesCommand::Private::cmsDeleteResult(const Error &err)
{
    cmsError = err;
    cmsJob = nullptr;
    if (!pgpJob) {
        showErrorsAndFinish();
    }
}

void DeleteCertificatesCommand::Private::cancelJobs()
{
    if (cmsJob) {
        cmsJob->slotCancel();
    }
    if (pgpJob) {
        pgpJob->slotCancel();
    }
}

#undef d
#undef q

#include "moc_deletecertificatescommand.cpp"
