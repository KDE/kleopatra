/* -*- mode: c++; c-basic-offset:4 -*-
    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2022 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include <config-kleopatra.h>

#include "revokeuseridcommand.h"

#include "command_p.h"

#include <Libkleo/Formatting>
#include <Libkleo/GnuPG>

#include <KLocalizedString>

#include <QGpgME/Protocol>
#include <QGpgME/QuickJob>

#include <gpgme++/key.h>

#include "kleopatra_debug.h"

using namespace Kleo;
using namespace Kleo::Commands;
using namespace GpgME;

class RevokeUserIDCommand::Private : public Command::Private
{
    friend class ::Kleo::Commands::RevokeUserIDCommand;
    RevokeUserIDCommand *q_func() const
    {
        return static_cast<RevokeUserIDCommand *>(q);
    }

public:
    explicit Private(RevokeUserIDCommand *qq, const UserID &userId);
    ~Private() override;

    void startJob();

private:
    void createJob();
    void slotResult(const Error &err);
    void showErrorDialog(const Error &error);
    void showSuccessDialog();

private:
    GpgME::UserID userId;
    QPointer<QGpgME::QuickJob> job;
};

RevokeUserIDCommand::Private *RevokeUserIDCommand::d_func()
{
    return static_cast<Private *>(d.get());
}
const RevokeUserIDCommand::Private *RevokeUserIDCommand::d_func() const
{
    return static_cast<const Private *>(d.get());
}

#define d d_func()
#define q q_func()

RevokeUserIDCommand::Private::Private(RevokeUserIDCommand *qq, const UserID &userId)
    : Command::Private{qq}
    , userId{userId}
{
}

RevokeUserIDCommand::Private::~Private() = default;

void Commands::RevokeUserIDCommand::Private::startJob()
{
    createJob();
    if (!job) {
        finished();
        return;
    }
    const QString uidToRevoke = QString::fromUtf8(engineIsVersion(2, 3, 7) ? userId.uidhash() : userId.id());
    job->startRevUid(userId.parent(), uidToRevoke);
}

void RevokeUserIDCommand::Private::createJob()
{
    Q_ASSERT(!job);

    const auto backend = QGpgME::openpgp();
    if (!backend) {
        return;
    }

    const auto j = backend->quickJob();
    if (!j) {
        return;
    }

    connect(j, &QGpgME::Job::jobProgress, q, &Command::progress);
    connect(j, &QGpgME::QuickJob::result, q, [this](const GpgME::Error &err) {
        slotResult(err);
    });

    job = j;
}

void RevokeUserIDCommand::Private::slotResult(const Error &err)
{
    if (err.isCanceled()) {
    } else if (err) {
        showErrorDialog(err);
    } else {
        showSuccessDialog();
    }
    finished();
}

void RevokeUserIDCommand::Private::showErrorDialog(const Error &err)
{
    error(xi18nc("@info",
                 "<para>An error occurred while trying to revoke the user ID<nl/><emphasis>%1</emphasis>.</para>"
                 "<para><message>%2</message></para>",
                 QString::fromUtf8(userId.id()),
                 Formatting::errorAsString(err)),
          i18nc("@title:window", "Revocation Failed"));
}

void RevokeUserIDCommand::Private::showSuccessDialog()
{
    information(xi18nc("@info", "<para>The user ID<nl/><emphasis>%1</emphasis><nl/>has been revoked successfully.</para>", QString::fromUtf8(userId.id())),
                i18nc("@title:window", "Revocation Succeeded"));
}

RevokeUserIDCommand::RevokeUserIDCommand(const GpgME::UserID &userId)
    : Command{new Private{this, userId}}
{
}

RevokeUserIDCommand::~RevokeUserIDCommand()
{
}

void RevokeUserIDCommand::doStart()
{
    if (d->userId.isNull()) {
        d->finished();
        return;
    }

    const auto key = d->userId.parent();
    if (key.protocol() != GpgME::OpenPGP || !key.hasSecret()) {
        d->finished();
        return;
    }

    d->startJob();
}

void RevokeUserIDCommand::doCancel()
{
    if (d->job) {
        d->job->slotCancel();
    }
}

#undef d
#undef q

#include "moc_revokeuseridcommand.cpp"
