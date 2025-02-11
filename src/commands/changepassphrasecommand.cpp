/* -*- mode: c++; c-basic-offset:4 -*-
    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2010 Klarälvdalens Datakonsult AB

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include <config-kleopatra.h>

#include "changepassphrasecommand.h"

#include "command_p.h"

#include <Libkleo/Formatting>

#include <QGpgME/ChangePasswdJob>
#include <QGpgME/Protocol>

#include <gpgme++/key.h>

#include "kleopatra_debug.h"
#include <KLocalizedString>

#include <gpg-error.h>

using namespace Kleo;
using namespace Kleo::Commands;
using namespace GpgME;
using namespace QGpgME;

class ChangePassphraseCommand::Private : public Command::Private
{
    friend class ::Kleo::Commands::ChangePassphraseCommand;
    ChangePassphraseCommand *q_func() const
    {
        return static_cast<ChangePassphraseCommand *>(q);
    }

public:
    explicit Private(ChangePassphraseCommand *qq, KeyListController *c);
    ~Private() override;

    void init();

private:
    void slotResult(const Error &err);

private:
    void createJob();
    void startJob();
    void showErrorDialog(const Error &error);
    void showSuccessDialog();

private:
    GpgME::Key key;
    QPointer<ChangePasswdJob> job;
};

ChangePassphraseCommand::Private *ChangePassphraseCommand::d_func()
{
    return static_cast<Private *>(d.get());
}
const ChangePassphraseCommand::Private *ChangePassphraseCommand::d_func() const
{
    return static_cast<const Private *>(d.get());
}

#define d d_func()
#define q q_func()

ChangePassphraseCommand::Private::Private(ChangePassphraseCommand *qq, KeyListController *c)
    : Command::Private(qq, c)
    , key()
    , job()
{
}

ChangePassphraseCommand::Private::~Private()
{
    qCDebug(KLEOPATRA_LOG);
}

ChangePassphraseCommand::ChangePassphraseCommand(KeyListController *c)
    : Command(new Private(this, c))
{
    d->init();
}

ChangePassphraseCommand::ChangePassphraseCommand(QAbstractItemView *v, KeyListController *c)
    : Command(v, new Private(this, c))
{
    d->init();
}

ChangePassphraseCommand::ChangePassphraseCommand(const GpgME::Key &key)
    : Command(key, new Private(this, nullptr))
{
    d->init();
}

void ChangePassphraseCommand::Private::init()
{
}

ChangePassphraseCommand::~ChangePassphraseCommand()
{
    qCDebug(KLEOPATRA_LOG);
}

void ChangePassphraseCommand::doStart()
{
    const std::vector<Key> keys = d->keys();
    if (keys.size() != 1 || !keys.front().hasSecret()) {
        d->finished();
        return;
    }

    d->key = keys.front();

    d->createJob();
    d->startJob();
}

void ChangePassphraseCommand::Private::startJob()
{
    const Error err = job ? job->start(key) : Error::fromCode(GPG_ERR_NOT_SUPPORTED);
    if (err) {
        showErrorDialog(err);
        finished();
    }
}

void ChangePassphraseCommand::Private::slotResult(const Error &err)
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

void ChangePassphraseCommand::doCancel()
{
    qCDebug(KLEOPATRA_LOG);
    if (d->job) {
        d->job->slotCancel();
    }
}

void ChangePassphraseCommand::Private::createJob()
{
    Q_ASSERT(!job);

    const auto backend = (key.protocol() == GpgME::OpenPGP) ? QGpgME::openpgp() : QGpgME::smime();
    if (!backend) {
        return;
    }

    ChangePasswdJob *const j = backend->changePasswdJob();
    if (!j) {
        return;
    }

    connect(j, &QGpgME::Job::jobProgress, q, &Command::progress);
    connect(j, &ChangePasswdJob::result, q, [this](const GpgME::Error &result) {
        slotResult(result);
    });

    job = j;
}

void ChangePassphraseCommand::Private::showErrorDialog(const Error &err)
{
    error(i18n("<p>An error occurred while trying to change "
               "the passphrase for <b>%1</b>:</p><p>%2</p>",
               Formatting::formatForComboBox(key),
               Formatting::errorAsString(err)),
          i18n("Passphrase Change Error"));
}

void ChangePassphraseCommand::Private::showSuccessDialog()
{
    information(i18n("Passphrase changed successfully."), i18n("Passphrase Change Succeeded"));
}

#undef d
#undef q

#include "moc_changepassphrasecommand.cpp"
