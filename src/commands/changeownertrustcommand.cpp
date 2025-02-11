/* -*- mode: c++; c-basic-offset:4 -*-
    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2008 Klarälvdalens Datakonsult AB
    SPDX-FileCopyrightText: 2022 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include <config-kleopatra.h>

#include "changeownertrustcommand.h"

#include "command_p.h"

#include <Libkleo/Compliance>
#include <Libkleo/Formatting>
#include <Libkleo/KeyCache>

#include <KLocalizedString>

#include <QGpgME/ChangeOwnerTrustJob>
#include <QGpgME/Protocol>

#include <gpgme++/key.h>

#include "kleopatra_debug.h"

using namespace Kleo;
using namespace Kleo::Commands;
using namespace GpgME;
using namespace QGpgME;

class ChangeOwnerTrustCommand::Private : public Command::Private
{
    friend class ::Kleo::Commands::ChangeOwnerTrustCommand;
    ChangeOwnerTrustCommand *q_func() const
    {
        return static_cast<ChangeOwnerTrustCommand *>(q);
    }

public:
    Private(ChangeOwnerTrustCommand *qq, KeyListController *c);

private:
    void startJob(Key::OwnerTrust trust);
    void createJob();
    void slotResult(const Error &err);
    void showErrorDialog(const Error &error);
    void showSuccessDialog();

private:
    QPointer<ChangeOwnerTrustJob> job;
    Key::OwnerTrust trustToSet = Key::OwnerTrust::Unknown;
};

ChangeOwnerTrustCommand::Private *ChangeOwnerTrustCommand::d_func()
{
    return static_cast<Private *>(d.get());
}
const ChangeOwnerTrustCommand::Private *ChangeOwnerTrustCommand::d_func() const
{
    return static_cast<const Private *>(d.get());
}

#define d d_func()
#define q q_func()

ChangeOwnerTrustCommand::Private::Private(ChangeOwnerTrustCommand *qq, KeyListController *c)
    : Command::Private{qq, c}
{
}

ChangeOwnerTrustCommand::ChangeOwnerTrustCommand(QAbstractItemView *v, KeyListController *c)
    : Command{v, new Private{this, c}}
{
}

ChangeOwnerTrustCommand::~ChangeOwnerTrustCommand()
{
    qCDebug(KLEOPATRA_LOG) << this << __func__;
}

void ChangeOwnerTrustCommand::doStart()
{
    if (d->keys().size() != 1) {
        d->finished();
        return;
    }

    const Key key = d->key();
    if (key.protocol() != GpgME::OpenPGP) {
        d->finished();
        return;
    }

    const auto keyInfo = Formatting::formatForComboBox(key);

    if (key.hasSecret()) {
        const auto answer = KMessageBox::questionTwoActionsCancel(d->parentWidgetOrView(),
                                                                  xi18nc("@info", "Is '%1' your own certificate?", keyInfo),
                                                                  i18nc("@title:window", "Mark Own Certificate"),
                                                                  KGuiItem(i18nc("@action:button", "Yes, it's mine")),
                                                                  KGuiItem(i18nc("@action:button", "No, it's not mine")),
                                                                  KStandardGuiItem::cancel());
        switch (answer) {
        case KMessageBox::ButtonCode::PrimaryAction: {
            if (key.ownerTrust() < Key::Ultimate) {
                d->startJob(Key::OwnerTrust::Ultimate);
            }
            return;
        }
        case KMessageBox::ButtonCode::SecondaryAction: {
            if (key.ownerTrust() == Key::Ultimate) {
                d->startJob(Key::OwnerTrust::Unknown);
                return;
            }
            // else ask next question
            break;
        }
        case KMessageBox::Cancel: {
            d->canceled();
            return;
        }
        default:; // cannot happen
        }
    }

    if (key.ownerTrust() < Key::OwnerTrust::Full) {
        const auto text = (DeVSCompliance::isCompliant() && DeVSCompliance::allSubkeysAreCompliant(key))
            ? xi18nc("@info %1: a certificate, %2: name of a compliance mode",
                     "<para>Do you want to grant '%1' the power to mark certificates as %2 for you?</para>"
                     "<para><emphasis>This means that the owner of this certificate properly checks fingerprints "
                     "and confirms the identities of others.</emphasis></para>",
                     keyInfo,
                     DeVSCompliance::name())
            : xi18nc("@info %1: a certificate",
                     "<para>Do you want to grant '%1' the power to mark certificates as valid for you?</para>"
                     "<para><emphasis>This means that the owner of this certificate properly checks fingerprints "
                     "and confirms the identities of others.</emphasis></para>",
                     keyInfo);
        const auto answer = KMessageBox::questionTwoActions(d->parentWidgetOrView(),
                                                            text,
                                                            i18nc("@title:window", "Grant Certification Power"),
                                                            KGuiItem(i18nc("@action:button", "Grant Power")),
                                                            KStandardGuiItem::cancel());
        if (answer == KMessageBox::ButtonCode::PrimaryAction) {
            d->startJob(Key::OwnerTrust::Full);
        } else {
            d->canceled();
        }
    } else {
        const auto text = (DeVSCompliance::isCompliant() && DeVSCompliance::allSubkeysAreCompliant(key))
            ? xi18nc("@info %1: a certificate, %2: name of a compliance mode",
                     "<para>The certificate '%1' is empowered to mark other certificates as %2 for you.</para>"
                     "<para>Do you want to revoke this power?</para>",
                     keyInfo,
                     DeVSCompliance::name())
            : xi18nc("@info %1: a certificate",
                     "<para>The certificate '%1' is empowered to mark other certificates as valid for you.</para>"
                     "<para>Do you want to revoke this power?</para>",
                     keyInfo);
        const auto answer = KMessageBox::questionTwoActions(d->parentWidgetOrView(),
                                                            text,
                                                            i18nc("@title:window", "Revoke Certification Power"),
                                                            KGuiItem(i18nc("@action:button", "Revoke Power")),
                                                            KStandardGuiItem::cancel());
        if (answer == KMessageBox::ButtonCode::PrimaryAction) {
            d->startJob(Key::OwnerTrust::Unknown);
        } else {
            d->canceled();
        }
    }
}

void ChangeOwnerTrustCommand::Private::startJob(Key::OwnerTrust trust)
{
    trustToSet = trust;

    createJob();
    Q_ASSERT(job);

    if (const Error err = job->start(key(), trust)) {
        showErrorDialog(err);
        finished();
    }
}

void ChangeOwnerTrustCommand::Private::slotResult(const Error &err)
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

void ChangeOwnerTrustCommand::doCancel()
{
    qCDebug(KLEOPATRA_LOG) << this << __func__;
    if (d->job) {
        d->job->slotCancel();
    }
}

void ChangeOwnerTrustCommand::Private::createJob()
{
    Q_ASSERT(!job);

    ChangeOwnerTrustJob *const j = QGpgME::openpgp()->changeOwnerTrustJob();
    if (!j) {
        return;
    }

    connect(j, &QGpgME::Job::jobProgress, q, &Command::progress);
    connect(j, &ChangeOwnerTrustJob::result, q, [this](const GpgME::Error &result) {
        slotResult(result);
    });

    job = j;
}

void ChangeOwnerTrustCommand::Private::showErrorDialog(const Error &err)
{
    const auto keyInfo = Formatting::formatForComboBox(key());
    switch (trustToSet) {
    case Key::OwnerTrust::Ultimate:
        error(xi18nc("@info",
                     "<para>An error occurred while marking certificate '%1' as your certificate.</para>"
                     "<para><message>%2</message></para>",
                     keyInfo,
                     Formatting::errorAsString(err)));
        break;
    case Key::OwnerTrust::Full:
        error(xi18nc("@info",
                     "<para>An error occurred while granting certification power to '%1'.</para>"
                     "<para><message>%2</message></para>",
                     keyInfo,
                     Formatting::errorAsString(err)));
        break;
    default:
        error(xi18nc("@info",
                     "<para>An error occurred while revoking the certification power of '%1'.</para>"
                     "<para><message>%2</message></para>",
                     keyInfo,
                     Formatting::errorAsString(err)));
    }
}

void ChangeOwnerTrustCommand::Private::showSuccessDialog()
{
    auto updatedKey = key();
    updatedKey.update();
    KeyCache::mutableInstance()->insert(updatedKey);

    const auto keyInfo = Formatting::formatForComboBox(updatedKey);
    switch (updatedKey.ownerTrust()) {
    case Key::OwnerTrust::Ultimate:
        success(i18nc("@info", "Certificate '%1' was marked as your certificate.", keyInfo));
        break;
    case Key::OwnerTrust::Full:
        success(i18nc("@info", "Certification power was granted to '%1'.", keyInfo));
        break;
    default:
        success(i18nc("@info", "The certification power of '%1' was revoked.", keyInfo));
    }
}

#undef d
#undef q

#include "moc_changeownertrustcommand.cpp"
