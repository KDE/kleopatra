/* -*- mode: c++; c-basic-offset:4 -*-
    commands/revokecertificationcommand.cpp

    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2020, 2022 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include <config-kleopatra.h>

#include "revokecertificationcommand.h"

#include "command_p.h"

#include "exportopenpgpcertstoservercommand.h"

#include <kleopatra_debug.h>

#include <Libkleo/Algorithm>
#include <Libkleo/Formatting>
#include <Libkleo/KeyCache>
#include <Libkleo/KeyHelpers>

#include <KGuiItem>
#include <KLocalizedString>
#include <KMessageBox>
#include <KStandardGuiItem>

#include <QGpgME/Protocol>
#include <QGpgME/QuickJob>

#include <gpgme++/engineinfo.h>

using namespace Kleo;
using namespace Kleo::Commands;
using namespace GpgME;
using namespace QGpgME;

namespace
{

enum class InputType {
    Key,
    UserIDs,
    Certifications,
};

struct CertificationData {
    UserID userId;
    Key certificationKey;
    UserID::Signature signature;
};

struct KeyAndSignature {
    Key key;
    UserID::Signature signature;
};

static std::vector<UserID::Signature> revokableCertifications(const GpgME::UserID &userId)
{
    auto signatures = userId.signatures();
    std::sort(signatures.begin(), signatures.end());
    std::reverse(signatures.begin(), signatures.end());

    auto last = std::unique(signatures.begin(), signatures.end(), [](const auto &sig1, const auto &sig2) {
        return !qstricmp(sig1.signerKeyID(), sig2.signerKeyID());
    });
    signatures.erase(last, signatures.end());
    erase_if(signatures, [](const auto &certification) {
        return userCanRevokeCertification(certification) != CertificationCanBeRevoked;
    });

    std::reverse(signatures.begin(), signatures.end());
    return signatures;
}

static std::vector<KeyAndSignature> getCertificationKeys(const GpgME::UserID &userId)
{
    std::vector<KeyAndSignature> keys;
    if (userId.numSignatures() == 0) {
        qCWarning(KLEOPATRA_LOG) << __func__ << "- Error: Signatures of user ID" << QString::fromUtf8(userId.id()) << "not available";
        return keys;
    }

    const auto certifications = revokableCertifications(userId);
    std::transform(certifications.begin(), certifications.end(), std::back_inserter(keys), [](const auto &signature) {
        return KeyAndSignature{KeyCache::instance()->findByKeyIDOrFingerprint(signature.signerKeyID()), signature};
    });

    return keys;
}

static bool confirmRevocations(QWidget *parent, const std::vector<CertificationData> &certifications)
{
    KMessageBox::ButtonCode answer;
    if (certifications.size() == 1) {
        const auto [userId, certificationKey, signature] = certifications.front();
        const auto message = xi18nc("@info",
                                    "<para>You are about to revoke the certification of user ID<nl/>%1<nl/>made with the key<nl/>%2.</para>",
                                    QString::fromUtf8(userId.id()),
                                    Formatting::formatForComboBox(certificationKey));
        answer = KMessageBox::questionTwoActions(parent,
                                                 message,
                                                 i18nc("@title:window", "Confirm Revocation"),
                                                 KGuiItem{i18n("Revoke Certification")},
                                                 KStandardGuiItem::cancel());
    } else {
        QStringList l;
        Kleo::transform(certifications, std::back_inserter(l), [](const auto &c) {
            return i18n("User ID '%1' certified with key %2", QString::fromUtf8(c.userId.id()), Formatting::formatForComboBox(c.certificationKey));
        });
        const auto message = i18np("You are about to revoke the following certification:", //
                                   "You are about to revoke the following %1 certifications:",
                                   certifications.size());
        answer = KMessageBox::questionTwoActionsList(parent,
                                                     message,
                                                     l,
                                                     i18nc("@title:window", "Confirm Revocation"),
                                                     KGuiItem{i18n("Revoke Certifications")},
                                                     KStandardGuiItem::cancel());
    }
    return answer == KMessageBox::ButtonCode::PrimaryAction;
}

}

class RevokeCertificationCommand::Private : public Command::Private
{
    friend class ::Kleo::Commands::RevokeCertificationCommand;
    RevokeCertificationCommand *q_func() const
    {
        return static_cast<RevokeCertificationCommand *>(q);
    }

public:
    Private(InputType i, RevokeCertificationCommand *qq, KeyListController *c = nullptr);

    void init();

private:
    std::vector<CertificationData> getCertificationsToRevoke();
    void scheduleNextRevocation();
    QGpgME::QuickJob *createJob();
    void slotResult(const Error &err);

private:
    InputType inputType = InputType::Key;
    Key certificationTarget;
    std::vector<UserID> uids;
    std::vector<CertificationData> certificationsToRevoke;
    std::vector<CertificationData> completedRevocations;
    QPointer<QGpgME::QuickJob> job;
};

RevokeCertificationCommand::Private *RevokeCertificationCommand::d_func()
{
    return static_cast<Private *>(d.get());
}
const RevokeCertificationCommand::Private *RevokeCertificationCommand::d_func() const
{
    return static_cast<const Private *>(d.get());
}

#define d d_func()
#define q q_func()

RevokeCertificationCommand::Private::Private(InputType i, RevokeCertificationCommand *qq, KeyListController *c)
    : Command::Private{qq, c}
    , inputType{i}
{
}

void RevokeCertificationCommand::Private::init()
{
    const std::vector<Key> keys_ = keys();
    if (keys_.size() != 1) {
        qCWarning(KLEOPATRA_LOG) << q << "Expected exactly one key, but got" << keys_.size();
        return;
    }
    if (keys_.front().protocol() != GpgME::OpenPGP) {
        qCWarning(KLEOPATRA_LOG) << q << "Expected OpenPGP key, but got" << keys_.front().protocolAsString();
        return;
    }
    certificationTarget = keys_.front();
}

std::vector<CertificationData> RevokeCertificationCommand::Private::getCertificationsToRevoke()
{
    if (inputType != InputType::Certifications) {
        // ensure that the certifications of the key have been loaded
        if (certificationTarget.userID(0).numSignatures() == 0) {
            certificationTarget.update();
        }

        // build list of user IDs and revokable certifications
        const auto userIDsToConsider = (inputType == InputType::Key) ? certificationTarget.userIDs() : uids;
        for (const auto &userId : userIDsToConsider) {
            Kleo::transform(getCertificationKeys(userId), std::back_inserter(certificationsToRevoke), [userId](const auto &k) {
                return CertificationData{userId, k.key, k.signature};
            });
        }
    }

    Kleo::erase_if(certificationsToRevoke, [](const auto &c) {
        return c.certificationKey.isNull();
    });

    return certificationsToRevoke;
}

void RevokeCertificationCommand::Private::scheduleNextRevocation()
{
    if (!certificationsToRevoke.empty()) {
        const auto nextCertification = certificationsToRevoke.back();
        job = createJob();
        if (!job) {
            qCWarning(KLEOPATRA_LOG) << q << "Failed to create job";
            finished();
            return;
        }
        job->startRevokeSignature(certificationTarget, nextCertification.certificationKey, {nextCertification.userId});
    } else {
        if (std::any_of(completedRevocations.begin(), completedRevocations.end(), [](const auto &revocation) {
                return revocation.signature.isExportable();
            })) {
            const auto message = xi18ncp("@info",
                                         "<para>The certification has been revoked successfully.</para>"
                                         "<para>Do you want to publish the revocation?</para>",
                                         "<para>%1 certifications have been revoked successfully.</para>"
                                         "<para>Do you want to publish the revocations?</para>",
                                         completedRevocations.size());
            const auto yesButton = KGuiItem{i18ncp("@action:button", "Publish Revocation", "Publish Revocations", completedRevocations.size()),
                                            QIcon::fromTheme(QStringLiteral("view-certificate-export-server"))};
            const auto answer = KMessageBox::questionTwoActions(parentWidgetOrView(),
                                                                message,
                                                                i18nc("@title:window", "Confirm Publication"),
                                                                yesButton,
                                                                KStandardGuiItem::cancel(),
                                                                {},
                                                                KMessageBox::Notify | KMessageBox::Dangerous);
            if (answer == KMessageBox::ButtonCode::PrimaryAction) {
                const auto cmd = new ExportOpenPGPCertsToServerCommand{certificationTarget};
                cmd->start();
            }
        }
        finished();
    }
}

void RevokeCertificationCommand::Private::slotResult(const Error &err)
{
    if (err.isCanceled()) {
        canceled();
        return;
    }

    if (err) {
        const auto failedRevocation = certificationsToRevoke.back();
        error(xi18nc("@info",
                     "<para>The revocation of the certification of user ID<nl/>%1<nl/>made with key<nl/>%2<nl/>failed:</para>"
                     "<para><message>%3</message></para>",
                     Formatting::prettyNameAndEMail(failedRevocation.userId),
                     Formatting::formatForComboBox(failedRevocation.certificationKey),
                     Formatting::errorAsString(err)));
        finished();
        return;
    }

    completedRevocations.push_back(certificationsToRevoke.back());
    certificationsToRevoke.pop_back();
    scheduleNextRevocation();
}

QGpgME::QuickJob *RevokeCertificationCommand::Private::createJob()
{
    const auto j = QGpgME::openpgp()->quickJob();
    if (j) {
        connect(j, &QGpgME::Job::jobProgress, q, &Command::progress);
        connect(j, &QGpgME::QuickJob::result, q, [this](const GpgME::Error &error) {
            slotResult(error);
        });
    }

    return j;
}

RevokeCertificationCommand::RevokeCertificationCommand(QAbstractItemView *v, KeyListController *c)
    : Command{v, new Private{InputType::Key, this, c}}
{
    d->init();
}

RevokeCertificationCommand::RevokeCertificationCommand(const GpgME::Key &key)
    : Command{key, new Private{InputType::Key, this}}
{
    d->init();
}

RevokeCertificationCommand::RevokeCertificationCommand(const GpgME::UserID &uid)
    : Command{uid.parent(), new Private{InputType::UserIDs, this}}
{
    std::vector<UserID>(1, uid).swap(d->uids);
    d->init();
}

RevokeCertificationCommand::RevokeCertificationCommand(const std::vector<GpgME::UserID> &uids)
    : Command{uids.empty() ? Key{} : uids.front().parent(), new Private{InputType::UserIDs, this}}
{
    d->uids = uids;
    d->init();
}

RevokeCertificationCommand::RevokeCertificationCommand(const GpgME::UserID::Signature &signature)
    : Command{signature.parent().parent(), new Private{InputType::Certifications, this}}
{
    if (!signature.isNull()) {
        const Key certificationKey = KeyCache::instance()->findByKeyIDOrFingerprint(signature.signerKeyID());
        d->certificationsToRevoke = {{signature.parent(), certificationKey, signature}};
    }
    d->init();
}

RevokeCertificationCommand::~RevokeCertificationCommand()
{
    qCDebug(KLEOPATRA_LOG) << this << __func__;
}

// static
bool RevokeCertificationCommand::isSupported()
{
    return engineInfo(GpgEngine).engineVersion() >= "2.2.24";
}

void RevokeCertificationCommand::doStart()
{
    if (d->certificationTarget.isNull()) {
        d->finished();
        return;
    }

    if (!std::ranges::all_of(d->uids, userIDBelongsToKey(d->certificationTarget))) {
        qCWarning(KLEOPATRA_LOG) << this << "User ID <-> Key mismatch!";
        d->finished();
        return;
    }

    const auto certificationsToRevoke = d->getCertificationsToRevoke();
    if (certificationsToRevoke.empty()) {
        switch (d->inputType) {
        case InputType::Key:
            d->information(i18n("You cannot revoke any certifications of this key."));
            break;
        case InputType::UserIDs:
            d->information(i18np("You cannot revoke any certifications of this user ID.", //
                                 "You cannot revoke any certifications of these user IDs.",
                                 d->uids.size()));
            break;
        case InputType::Certifications:
            d->information(i18n("You cannot revoke this certification."));
            break;
        }
        d->finished();
        return;
    }

    if (!confirmRevocations(d->parentWidgetOrView(), certificationsToRevoke)) {
        d->canceled();
        return;
    }

    d->scheduleNextRevocation();
}

void RevokeCertificationCommand::doCancel()
{
    qCDebug(KLEOPATRA_LOG) << this << __func__;
    if (d->job) {
        d->job->slotCancel();
    }
}

#undef d
#undef q

#include "moc_revokecertificationcommand.cpp"
