/*
    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2008 Klarälvdalens Datakonsult AB
    SPDX-FileCopyrightText: 2022 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include <config-kleopatra.h>

#include "adduseridcommand.h"

#include "command_p.h"

#include "dialogs/adduseriddialog.h"

#include <Libkleo/Formatting>
#include <QGpgME/Protocol>
#include <QGpgME/QuickJob>

#include <QObjectCleanupHandler>

#include <gpgme++/key.h>

#include "kleopatra_debug.h"
#include <KLocalizedString>

using namespace Kleo;
using namespace Kleo::Commands;
using namespace GpgME;

class AddUserIDCommand::Private : public Command::Private
{
    friend class ::Kleo::Commands::AddUserIDCommand;
    AddUserIDCommand *q_func() const
    {
        return static_cast<AddUserIDCommand *>(q);
    }

public:
    explicit Private(AddUserIDCommand *qq, KeyListController *c);
    ~Private() override;

private:
    void slotDialogAccepted();
    void slotDialogRejected();
    void slotResult(const Error &err);

private:
    void ensureDialogCreated();
    void createJob();
    void showErrorDialog(const Error &error);
    void showSuccessDialog();

private:
    GpgME::Key key;
    QObjectCleanupHandler cleaner;
    QPointer<AddUserIDDialog> dialog;
    QPointer<QGpgME::QuickJob> job;
};

AddUserIDCommand::Private *AddUserIDCommand::d_func()
{
    return static_cast<Private *>(d.get());
}
const AddUserIDCommand::Private *AddUserIDCommand::d_func() const
{
    return static_cast<const Private *>(d.get());
}

#define d d_func()
#define q q_func()

AddUserIDCommand::Private::Private(AddUserIDCommand *qq, KeyListController *c)
    : Command::Private{qq, c}
{
}

AddUserIDCommand::Private::~Private() = default;

AddUserIDCommand::AddUserIDCommand(QAbstractItemView *v, KeyListController *c)
    : Command{v, new Private{this, c}}
{
}

AddUserIDCommand::AddUserIDCommand(const GpgME::Key &key)
    : Command{key, new Private{this, nullptr}}
{
}

AddUserIDCommand::~AddUserIDCommand()
{
    qCDebug(KLEOPATRA_LOG).nospace() << this << "::" << __func__;
}

void AddUserIDCommand::doStart()
{
    const std::vector<Key> keys = d->keys();
    if (keys.size() != 1) {
        d->finished();
        return;
    }

    d->key = keys.front();
    if (d->key.protocol() != GpgME::OpenPGP //
        || !d->key.hasSecret()) {
        d->finished();
        return;
    }

    d->ensureDialogCreated();

    const UserID uid = d->key.userID(0);

    d->dialog->setName(QString::fromUtf8(uid.name()));
    d->dialog->setEmail(Formatting::prettyEMail(uid.email(), uid.id()));

    d->dialog->show();
}

void AddUserIDCommand::Private::slotDialogAccepted()
{
    Q_ASSERT(dialog);

    createJob();
    if (!job) {
        finished();
        return;
    }
    job->startAddUid(key, dialog->userID());
}

void AddUserIDCommand::Private::slotDialogRejected()
{
    canceled();
}

void AddUserIDCommand::Private::slotResult(const Error &err)
{
    if (err.isCanceled()) {
    } else if (err) {
        showErrorDialog(err);
    } else {
        showSuccessDialog();
    }
    finished();
}

void AddUserIDCommand::doCancel()
{
    qCDebug(KLEOPATRA_LOG).nospace() << this << "::" << __func__;
    if (d->job) {
        d->job->slotCancel();
    }
}

void AddUserIDCommand::Private::ensureDialogCreated()
{
    if (dialog) {
        return;
    }

    dialog = new AddUserIDDialog;
    cleaner.add(dialog);
    applyWindowID(dialog);

    connect(dialog, &QDialog::accepted, q, [this]() {
        slotDialogAccepted();
    });
    connect(dialog, &QDialog::rejected, q, [this]() {
        slotDialogRejected();
    });
}

void AddUserIDCommand::Private::createJob()
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

void AddUserIDCommand::Private::showErrorDialog(const Error &err)
{
    error(xi18nc("@info",
                 "<para>An error occurred while trying to add the user ID: "
                 "<message>%1</message></para>",
                 Formatting::errorAsString(err)),
          i18nc("@title:window", "Add User ID Error"));
}

void AddUserIDCommand::Private::showSuccessDialog()
{
    information(i18nc("@info", "User ID successfully added."), //
                i18nc("@title:window", "Add User ID Succeeded"));
}

#undef d
#undef q

#include "moc_adduseridcommand.cpp"
