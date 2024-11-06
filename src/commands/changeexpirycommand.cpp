/* -*- mode: c++; c-basic-offset:4 -*-
    commands/changeexpirycommand.cpp

    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2008 Klarälvdalens Datakonsult AB
    SPDX-FileCopyrightText: 2021 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include <config-kleopatra.h>

#include "changeexpirycommand.h"
#include "command_p.h"

#include "dialogs/expirydialog.h"

#include <Libkleo/Expiration>
#include <Libkleo/Formatting>

#include <KLocalizedString>

#include <QGpgME/ChangeExpiryJob>
#include <QGpgME/Protocol>

#include <QDateTime>

#include <gpgme++/key.h>

#include <algorithm>

#include "kleopatra_debug.h"

using namespace Kleo;
using namespace Kleo::Commands;
using namespace Kleo::Dialogs;
using namespace GpgME;
using namespace QGpgME;

namespace
{
bool subkeyHasSameExpirationAsPrimaryKey(const Subkey &subkey)
{
    // we allow for a difference in expiration of up to 1 hour (= 3600 seconds)
    static const auto maxExpirationDifference = 3600;

    Q_ASSERT(!subkey.isNull());
    const auto key = subkey.parent();
    const auto primaryKey = key.subkey(0);
    const auto primaryExpiration = quint32(primaryKey.expirationTime());
    const auto subkeyExpiration = quint32(subkey.expirationTime());
    if (primaryExpiration != 0 && subkeyExpiration != 0) {
        return (primaryExpiration == subkeyExpiration) //
            || ((primaryExpiration > subkeyExpiration) && (primaryExpiration - subkeyExpiration <= maxExpirationDifference)) //
            || ((primaryExpiration < subkeyExpiration) && (subkeyExpiration - primaryExpiration <= maxExpirationDifference));
    }
    return primaryKey.neverExpires() && subkey.neverExpires();
}

bool allNotRevokedSubkeysHaveSameExpirationAsPrimaryKey(const Key &key)
{
    Q_ASSERT(!key.isNull() && key.numSubkeys() > 0);
    const auto subkeys = key.subkeys();
    return std::all_of(std::begin(subkeys), std::end(subkeys), [](const auto &subkey) {
        // revoked subkeys are ignored by gpg --quick-set-expire when updating the expiration of all subkeys;
        // check if expiration of subkey is (more or less) the same as the expiration of the primary key
        return subkey.isRevoked() || subkeyHasSameExpirationAsPrimaryKey(subkey);
    });
}
}

class ChangeExpiryCommand::Private : public Command::Private
{
    friend class ::Kleo::Commands::ChangeExpiryCommand;
    ChangeExpiryCommand *q_func() const
    {
        return static_cast<ChangeExpiryCommand *>(q);
    }

public:
    explicit Private(ChangeExpiryCommand *qq, KeyListController *c);
    ~Private() override;

private:
    void slotDialogAccepted();
    void slotDialogRejected();
    void slotResult(const Error &err);

private:
    void ensureDialogCreated(ExpiryDialog::Mode mode);
    void createJob();
    void showErrorDialog(const Error &error);
    void showSuccessDialog();

private:
    GpgME::Key key;
    GpgME::Subkey subkey;
    QPointer<ExpiryDialog> dialog;
    QPointer<ChangeExpiryJob> job;
};

ChangeExpiryCommand::Private *ChangeExpiryCommand::d_func()
{
    return static_cast<Private *>(d.get());
}
const ChangeExpiryCommand::Private *ChangeExpiryCommand::d_func() const
{
    return static_cast<const Private *>(d.get());
}

#define d d_func()
#define q q_func()

ChangeExpiryCommand::Private::Private(ChangeExpiryCommand *qq, KeyListController *c)
    : Command::Private{qq, c}
{
}

ChangeExpiryCommand::Private::~Private() = default;

void ChangeExpiryCommand::Private::slotDialogAccepted()
{
    Q_ASSERT(dialog);

    static const QTime END_OF_DAY{23, 59, 00};

    const QDateTime expiry{dialog->dateOfExpiry(), END_OF_DAY};

    qCDebug(KLEOPATRA_LOG) << "expiry" << expiry;

    createJob();
    Q_ASSERT(job);

    std::vector<Subkey> subkeysToUpdate;
    if (!subkey.isNull()) {
        // change expiration of a single subkey
        if (subkey.keyID() != key.keyID()) { // ignore the primary subkey
            subkeysToUpdate.push_back(subkey);
        }
    } else {
        // change expiration of the (primary) key and, optionally, of some subkeys
        job->setOptions(ChangeExpiryJob::UpdatePrimaryKey);
        if (dialog->updateExpirationOfAllSubkeys() && key.numSubkeys() > 1) {
            // explicitly list the subkeys for which the expiration should be changed
            // together with the expiration of the (primary) key, so that already expired
            // subkeys are also updated
            const auto subkeys = key.subkeys();
            std::copy_if(std::next(subkeys.begin()), subkeys.end(), std::back_inserter(subkeysToUpdate), [](const auto &subkey) {
                // skip revoked subkeys which would anyway be ignored by gpg;
                // also skip subkeys without explicit expiration because they inherit the primary key's expiration;
                // include all subkeys that are not yet expired or that expired around the same time as the primary key
                return !subkey.isRevoked() //
                    && !subkey.neverExpires() //
                    && (!subkey.isExpired() || subkeyHasSameExpirationAsPrimaryKey(subkey));
            });
        }
    }

    if (const Error err = job->start(key, expiry, subkeysToUpdate)) {
        showErrorDialog(err);
        finished();
    }
}

void ChangeExpiryCommand::Private::slotDialogRejected()
{
    canceled();
}

void ChangeExpiryCommand::Private::slotResult(const Error &err)
{
    if (err.isCanceled())
        ;
    else if (err) {
        showErrorDialog(err);
    } else {
        showSuccessDialog();
    }
    finished();
}

void ChangeExpiryCommand::Private::ensureDialogCreated(ExpiryDialog::Mode mode)
{
    if (dialog) {
        return;
    }

    dialog = new ExpiryDialog{mode};
    applyWindowID(dialog);
    dialog->setAttribute(Qt::WA_DeleteOnClose);

    connect(dialog, &QDialog::accepted, q, [this]() {
        slotDialogAccepted();
    });
    connect(dialog, &QDialog::rejected, q, [this]() {
        slotDialogRejected();
    });
}

void ChangeExpiryCommand::Private::createJob()
{
    Q_ASSERT(!job);

    const auto backend = (key.protocol() == GpgME::OpenPGP) ? QGpgME::openpgp() : QGpgME::smime();
    if (!backend) {
        return;
    }

    ChangeExpiryJob *const j = backend->changeExpiryJob();
    if (!j) {
        return;
    }

    connect(j, &QGpgME::Job::jobProgress, q, &Command::progress);
    connect(j, &ChangeExpiryJob::result, q, [this](const auto &err) {
        slotResult(err);
    });

    job = j;
}

void ChangeExpiryCommand::Private::showErrorDialog(const Error &err)
{
    error(
        i18n("<p>An error occurred while trying to change "
             "the end of the validity period for <b>%1</b>:</p><p>%2</p>",
             Formatting::formatForComboBox(key),
             Formatting::errorAsString(err)));
}

void ChangeExpiryCommand::Private::showSuccessDialog()
{
    success(i18n("End of validity period changed successfully."));
}

ChangeExpiryCommand::ChangeExpiryCommand(KeyListController *c)
    : Command{new Private{this, c}}
{
}

ChangeExpiryCommand::ChangeExpiryCommand(QAbstractItemView *v, KeyListController *c)
    : Command{v, new Private{this, c}}
{
}

ChangeExpiryCommand::ChangeExpiryCommand(const GpgME::Key &key)
    : Command{key, new Private{this, nullptr}}
{
}

ChangeExpiryCommand::~ChangeExpiryCommand() = default;

void ChangeExpiryCommand::setSubkey(const GpgME::Subkey &subkey)
{
    d->subkey = subkey;
}

void ChangeExpiryCommand::doStart()
{
    const std::vector<Key> keys = d->keys();
    if (keys.size() != 1 //
        || keys.front().protocol() != GpgME::OpenPGP //
        || !keys.front().hasSecret() //
        || keys.front().subkey(0).isNull()) {
        d->finished();
        return;
    }

    d->key = keys.front();

    if (!d->subkey.isNull() && d->subkey.parent().primaryFingerprint() != d->key.primaryFingerprint()) {
        qDebug() << "Invalid subkey" << d->subkey.fingerprint() << ": Not a subkey of key" << d->key.primaryFingerprint();
        d->finished();
        return;
    }

    ExpiryDialog::Mode mode;
    if (!d->subkey.isNull()) {
        mode = ExpiryDialog::Mode::UpdateIndividualSubkey;
    } else {
        // count the number of (real) subkeys for which the user has the choice to update
        // the expiration together with the primary key
        const auto subkeys = d->key.subkeys();
        const auto numSubkeys = std::count_if(std::next(subkeys.begin()), subkeys.end(), [](const auto &subkey) {
            // skip revoked subkeys which would anyway be ignored by gpg;
            // also skip subkeys without explicit expiration because they inherit the primary key's expiration;
            // include all subkeys that are not yet expired or that expired around the same time as the primary key
            return !subkey.isRevoked() //
                && !subkey.neverExpires() //
                && (!subkey.isExpired() || subkeyHasSameExpirationAsPrimaryKey(subkey));
        });
        if (numSubkeys == 0) {
            mode = ExpiryDialog::Mode::UpdateCertificateWithoutSubkeys;
        } else {
            mode = ExpiryDialog::Mode::UpdateCertificateWithSubkeys;
        }
    }
    d->ensureDialogCreated(mode);
    Q_ASSERT(d->dialog);
    const Subkey subkey = !d->subkey.isNull() ? d->subkey : d->key.subkey(0);
    d->dialog->setDateOfExpiry((subkey.neverExpires() //
                                    ? QDate{} //
                                    : Kleo::Expiration::defaultExpirationDate(Kleo::Expiration::ExpirationOnUnlimitedValidity::InternalDefaultExpiration)));
    if (mode == ExpiryDialog::Mode::UpdateIndividualSubkey && subkey.keyID() != subkey.parent().keyID()) {
        d->dialog->setPrimaryKey(subkey.parent());
    } else if (mode == ExpiryDialog::Mode::UpdateCertificateWithSubkeys) {
        d->dialog->setUpdateExpirationOfAllSubkeys(allNotRevokedSubkeysHaveSameExpirationAsPrimaryKey(d->key));
    }

    d->dialog->show();
}

void ChangeExpiryCommand::doCancel()
{
    if (d->job) {
        d->job->slotCancel();
    }
}

#undef d
#undef q

#include "moc_changeexpirycommand.cpp"
