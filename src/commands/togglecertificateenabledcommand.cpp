/*
    SPDX-FileCopyrightText: 2024 g10 Code GmbH
    SPDX-FileContributor: Tobias Fella <tobias.fella@gnupg.com>

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include "togglecertificateenabledcommand.h"

#include "command_p.h"

#include <Libkleo/Formatting>
#include <Libkleo/KeyFilterManager>

#include <QGpgME/Protocol>
#include <QGpgME/QuickJob>

#include <gpgme++/engineinfo.h>
#include <gpgme++/key.h>

#include <gpgme.h>

#include <KLocalizedString>

using namespace Qt::Literals::StringLiterals;
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
    if (!d->key().isDisabled()) {
        const auto filterName = KeyFilterManager::instance()->keyFilterByID(u"disabled-filter"_s)->name();
        auto result = KMessageBox::warningContinueCancel(
            d->parentWidgetOrView(),
            xi18nc("@info",
                   "<para>Disabled certificates cannot be selected for signing or encryption. "
                   "They are only visible when the <interface>%2</interface> filter is active.</para>"
                   "<para>You can undo this action at any time by switching to the "
                   "<interface>%2</interface> filter and enabling the certificate again.</para>"
                   "<para><emphasis strong='true'>Are you sure you want to disable and hide the following certificate?</emphasis></para>"
                   "<list><item>%1</item></list>",
                   Formatting::summaryLine(d->key()),
                   filterName),
            i18nc("@title:dialog", "Disable Certificate"),
            KGuiItem(i18nc("@action:button", "Disable Certificate")),
            KStandardGuiItem::cancel(),
            u"disable-certificate-warning"_s);
        if (result == KMessageBox::Cancel) {
            d->canceled();
            return;
        }
    }

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
