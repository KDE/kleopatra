/*
    SPDX-FileCopyrightText: 2024 g10 Code GmbH
    SPDX-FileContributor: Tobias Fella <tobias.fella@gnupg.com>

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include "addadskcommand.h"

#include "command_p.h"
#include "dialogs/addadskdialog.h"

#include <Libkleo/Formatting>

#include <KLocalizedString>

#include <QGpgME/Protocol>
#include <QGpgME/QuickJob>

#include <gpgme++/key.h>

#include <gpgme.h>

using namespace Kleo;
using namespace Kleo::Commands;
using namespace Kleo::Dialogs;
using namespace GpgME;
using namespace QGpgME;

class AddADSKCommand::Private : public Command::Private
{
    AddADSKCommand *q_func() const
    {
        return static_cast<AddADSKCommand *>(q);
    }

public:
    explicit Private(AddADSKCommand *qq, KeyListController *c);
    ~Private() override;

    void slotDialogAccepted();
    void slotDialogRejected();
    void slotResult(const Error &err);

    void ensureDialogCreated();
    void createJob();
    void showErrorDialog(const Error &error);
    void showSuccessDialog();

    QPointer<AddADSKDialog> dialog;
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

AddADSKCommand::Private::Private(AddADSKCommand *qq, KeyListController *c)
    : Command::Private{qq, c}
{
}

AddADSKCommand::Private::~Private() = default;

void AddADSKCommand::Private::slotDialogAccepted()
{
    Q_ASSERT(dialog);

    createJob();
    for (const auto &subkey : dialog->adsk().subkeys()) {
        if (subkey.canEncrypt() && !subkey.isBad()) {
            job->startAddAdsk(key(), subkey);
            break;
        }
    }
}

void AddADSKCommand::Private::slotDialogRejected()
{
    Q_EMIT q->canceled();
    finished();
}

void AddADSKCommand::Private::slotResult(const Error &err)
{
    if (err.isCanceled()) {
        //
    } else if (err) {
        showErrorDialog(err);
    } else {
        showSuccessDialog();
    }
    finished();
}

void AddADSKCommand::Private::ensureDialogCreated()
{
    if (dialog) {
        return;
    }

    dialog = new AddADSKDialog{key()};
    applyWindowID(dialog);
    dialog->setAttribute(Qt::WA_DeleteOnClose);

    connect(dialog, &QDialog::accepted, q, [this]() {
        slotDialogAccepted();
    });
    connect(dialog, &QDialog::rejected, q, [this]() {
        slotDialogRejected();
    });
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
    error(i18nc("'ADSK' means 'Additional Decryption Subkey'; Don't try translating it, though.",
                "<p>An error occurred while trying to add "
                "a new ADSK to <b>%1</b>:</p><p>%2</p>",
                Formatting::formatForComboBox(key()),
                Formatting::errorAsString(err)));
}

void AddADSKCommand::Private::showSuccessDialog()
{
    success(i18nc("'ADSK' means 'Additional Decryption Subkey'; Don't try translating it, though.", "ADSK added successfully."));
}

AddADSKCommand::AddADSKCommand(const GpgME::Key &key)
    : Command{key, new Private{this, nullptr}}
{
}

AddADSKCommand::~AddADSKCommand() = default;

void AddADSKCommand::doStart()
{
    d->ensureDialogCreated();
    Q_ASSERT(d->dialog);

    d->dialog->show();
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
