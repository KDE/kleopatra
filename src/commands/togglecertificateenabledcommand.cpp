/*
    SPDX-FileCopyrightText: 2024 g10 Code GmbH
    SPDX-FileContributor: Tobias Fella <tobias.fella@gnupg.com>

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include "togglecertificateenabledcommand.h"

#include "command_p.h"

#include <Libkleo/Formatting>

#include <QGpgME/Protocol>
#include <QGpgME/QuickJob>

#include <gpgme++/engineinfo.h>
#include <gpgme++/key.h>

#include <gpgme.h>

#include <KLocalizedString>

using namespace Kleo::Commands;
using namespace GpgME;
using namespace QGpgME;

class ToggleCertificateEnabledCommand::Private : public Command::Private
{
    ToggleCertificateEnabledCommand *q_func() const
    {
        return static_cast<ToggleCertificateEnabledCommand *>(q);
    }

public:
    explicit Private(ToggleCertificateEnabledCommand *qq, KeyListController *c = nullptr);
    ~Private() override;

    void slotResult(const Error &err);

    void createJob();
    QPointer<QuickJob> job;
};

ToggleCertificateEnabledCommand::Private *ToggleCertificateEnabledCommand::d_func()
{
    return static_cast<Private *>(d.get());
}
const ToggleCertificateEnabledCommand::Private *ToggleCertificateEnabledCommand::d_func() const
{
    return static_cast<const Private *>(d.get());
}

#define d d_func()
#define q q_func()

ToggleCertificateEnabledCommand::Private::Private(ToggleCertificateEnabledCommand *qq, KeyListController *c)
    : Command::Private{qq, c}
{
}
ToggleCertificateEnabledCommand::ToggleCertificateEnabledCommand(QAbstractItemView *v, KeyListController *c)
    : Command{v, new Private{this, c}}
{
}

ToggleCertificateEnabledCommand::Private::~Private() = default;

void ToggleCertificateEnabledCommand::Private::slotResult(const Error &err)
{
    if (err.isCanceled()) {
        canceled();
        return;
    }

    if (err) {
        if (key().isDisabled()) {
            error(xi18nc("@info", "<para>Failed to enable certificate:</para><para><message>%1</message></para>", Formatting::errorAsString(err)));
        } else {
            error(xi18nc("@info", "<para>Failed to disable certificate:</para><para><message>%1</message></para>", Formatting::errorAsString(err)));
        }
    }
    finished();
}

void ToggleCertificateEnabledCommand::Private::createJob()
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
    connect(j, &QuickJob::result, q, [this](const auto &err) {
        slotResult(err);
    });

    job = j;
}

ToggleCertificateEnabledCommand::~ToggleCertificateEnabledCommand() = default;

void ToggleCertificateEnabledCommand::doStart()
{
    d->createJob();

#if GPGME_VERSION_NUMBER >= 0x011800 // 1.24.0
    d->job->startSetKeyEnabled(d->key(), d->key().isDisabled());
#endif
}

void ToggleCertificateEnabledCommand::doCancel()
{
    if (d->job) {
        d->job->slotCancel();
    }
}

// static
bool ToggleCertificateEnabledCommand::isSupported()
{
#if GPGME_VERSION_NUMBER >= 0x011800 // 1.24.0
    return engineInfo(GpgEngine).engineVersion() >= "2.4.6";
#else
    return false;
#endif
}

#undef d
#undef q

#include "moc_togglecertificateenabledcommand.cpp"
