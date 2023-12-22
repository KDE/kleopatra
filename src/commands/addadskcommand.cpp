/*
    SPDX-FileCopyrightText: 2024 g10 Code GmbH
    SPDX-FileContributor: Tobias Fella <tobias.fella@gnupg.com>

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include "addadskcommand.h"

#include "command_p.h"

#include <Libkleo/Formatting>

#include <KLocalizedString>

#include <QGpgME/Protocol>
#include <QGpgME/QuickJob>

#include <gpgme++/key.h>

#include <gpgme.h>

using namespace Kleo::Commands;
using namespace GpgME;
using namespace QGpgME;

class AddADSKCommand::Private : public Command::Private
{
    AddADSKCommand *q_func() const
    {
        return static_cast<AddADSKCommand *>(q);
    }

public:
    explicit Private(AddADSKCommand *qq);
    ~Private() override;

    void slotResult(const Error &err);

    void createJob();
    void showErrorDialog(const Error &error);
    void showSuccessDialog();

    QPointer<QuickJob> job;
};

AddADSKCommand::Private *AddADSKCommand::d_func()
{
    return static_cast<Private *>(d.get());
}
const AddADSKCommand::Private *AddADSKCommand::d_func() const
{
    return static_cast<const Private *>(d.get());
}

#define d d_func()
#define q q_func()

AddADSKCommand::Private::Private(AddADSKCommand *qq)
    : Command::Private{qq}
{
}

AddADSKCommand::Private::~Private() = default;

void AddADSKCommand::Private::slotResult(const Error &err)
{
    if (err.isCanceled()) {
        canceled();
        return;
    }

    if (err) {
        showErrorDialog(err);
    } else {
        showSuccessDialog();
    }
    finished();
}

void AddADSKCommand::Private::createJob()
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

void AddADSKCommand::Private::showErrorDialog(const Error &err)
{
    error(i18nc("@info",
                "<p>An error occurred while trying to add "
                "an ADSK to <b>%1</b>:</p><p>%2</p>",
                Formatting::formatForComboBox(key()),
                Formatting::errorAsString(err)));
}

void AddADSKCommand::Private::showSuccessDialog()
{
    success(i18nc("@info", "ADSK added successfully."));
}

AddADSKCommand::AddADSKCommand(const GpgME::Key &key)
    : Command{key, new Private{this}}
{
}

AddADSKCommand::~AddADSKCommand() = default;

void AddADSKCommand::doStart()
{
    auto code = KMessageBox::warningContinueCancel(d->parentWidgetOrView(),
                                                   i18nc("@info",
                                                         "By adding an ADSK to your certificate, you allow the owner of the ADSK to decrypt all new messages that "
                                                         "are encrypted for your certificate. Do you want to add the ADSK specified in the GnuPG configuration to your certificate?"),
                                                   i18nc("@title:dialog", "Add ADSK"),
                                                   KGuiItem(i18n("Add ADSK"), QStringLiteral("dialog-ok")));
    if (code == KMessageBox::Cancel) {
        canceled();
        return;
    }
    d->createJob();
#if GPGME_VERSION_NUMBER >= 0x011800 // 1.24.0
    d->job->startAddAdsk(d->key(), "default");
#endif
}

void AddADSKCommand::doCancel()
{
    if (d->job) {
        d->job->slotCancel();
    }
}

#undef d
#undef q

#include "moc_addadskcommand.cpp"
