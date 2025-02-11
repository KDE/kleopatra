/* -*- mode: c++; c-basic-offset:4 -*-
    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2022 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include <config-kleopatra.h>

#include "setprimaryuseridcommand.h"

#include "command_p.h"

#include <Libkleo/Formatting>

#include <KLocalizedString>

#include <QGpgME/SetPrimaryUserIDJob>

#include <QGpgME/Protocol>
#include <gpgme++/key.h>

#include "kleopatra_debug.h"

using namespace Kleo;
using namespace Kleo::Commands;
using namespace GpgME;

class SetPrimaryUserIDCommand::Private : public Command::Private
{
    friend class ::Kleo::Commands::SetPrimaryUserIDCommand;
    SetPrimaryUserIDCommand *q_func() const
    {
        return static_cast<SetPrimaryUserIDCommand *>(q);
    }

public:
    explicit Private(SetPrimaryUserIDCommand *qq, const UserID &userId);
    ~Private() override;

    void startJob();

private:
    void createJob();
    void slotResult(const Error &err);
    void showErrorDialog(const Error &error);
    void showSuccessDialog();

private:
    GpgME::UserID userId;
    QPointer<QGpgME::SetPrimaryUserIDJob> job;
};

SetPrimaryUserIDCommand::Private *SetPrimaryUserIDCommand::d_func()
{
    return static_cast<Private *>(d.get());
}
const SetPrimaryUserIDCommand::Private *SetPrimaryUserIDCommand::d_func() const
{
    return static_cast<const Private *>(d.get());
}

#define d d_func()
#define q q_func()

SetPrimaryUserIDCommand::Private::Private(SetPrimaryUserIDCommand *qq, const UserID &userId)
    : Command::Private{qq}
    , userId{userId}
{
}

SetPrimaryUserIDCommand::Private::~Private() = default;

void Commands::SetPrimaryUserIDCommand::Private::startJob()
{
    createJob();
    if (!job) {
        finished();
        return;
    }
    job->start(userId);
}

void SetPrimaryUserIDCommand::Private::createJob()
{
    Q_ASSERT(!job);

    const auto backend = QGpgME::openpgp();
    if (!backend) {
        return;
    }

    const auto j = backend->setPrimaryUserIDJob();
    if (!j) {
        return;
    }

    connect(j, &QGpgME::Job::jobProgress, q, &Command::progress);
    connect(j, &QGpgME::SetPrimaryUserIDJob::result, q, [this](const GpgME::Error &err) {
        slotResult(err);
    });

    job = j;
}

void SetPrimaryUserIDCommand::Private::slotResult(const Error &err)
{
    if (err.isCanceled()) {
    } else if (err) {
        showErrorDialog(err);
    } else {
        showSuccessDialog();
    }
    finished();
}

void SetPrimaryUserIDCommand::Private::showErrorDialog(const Error &err)
{
    error(xi18nc("@info",
                 "<para>An error occurred while trying to flag the user ID<nl/><emphasis>%1</emphasis><nl/>as the primary user ID.</para>"
                 "<para><message>%2</message></para>",
                 QString::fromUtf8(userId.id()),
                 Formatting::errorAsString(err)));
}

void SetPrimaryUserIDCommand::Private::showSuccessDialog()
{
    success(xi18nc("@info",
                   "<para>The user ID<nl/><emphasis>%1</emphasis><nl/>has been flagged successfully as the primary user ID.</para>",
                   QString::fromUtf8(userId.id())));
}

SetPrimaryUserIDCommand::SetPrimaryUserIDCommand(const GpgME::UserID &userId)
    : Command{new Private{this, userId}}
{
}

SetPrimaryUserIDCommand::~SetPrimaryUserIDCommand()
{
    qCDebug(KLEOPATRA_LOG).nospace() << this << "::" << __func__;
}

void SetPrimaryUserIDCommand::doStart()
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

void SetPrimaryUserIDCommand::doCancel()
{
    qCDebug(KLEOPATRA_LOG).nospace() << this << "::" << __func__;
    if (d->job) {
        d->job->slotCancel();
    }
}

#undef d
#undef q

#include "moc_setprimaryuseridcommand.cpp"
