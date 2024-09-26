/* -*- mode: c++; c-basic-offset:4 -*-
    commands/revokekeycommand.cpp

    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2022 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include <config-kleopatra.h>

#include "command_p.h"
#include "commands/exportopenpgpcertstoservercommand.h"
#include "dialogs/revokekeydialog.h"
#include "kleopatra_debug.h"
#include "revokekeycommand.h"

#include <Libkleo/Formatting>
#include <Libkleo/GnuPG>
#include <Libkleo/KeyCache>

#include <QGpgME/ExportJob>
#include <QGpgME/Protocol>
#include <QGpgME/RevokeKeyJob>

#include <gpgme.h>

#include <KFileUtils>
#include <KLocalizedString>

#include <QFile>
#include <QFileInfo>
#include <QStandardPaths>

using namespace Kleo;
using namespace GpgME;

class RevokeKeyCommand::Private : public Command::Private
{
    friend class ::RevokeKeyCommand;
    RevokeKeyCommand *q_func() const
    {
        return static_cast<RevokeKeyCommand *>(q);
    }

public:
    explicit Private(RevokeKeyCommand *qq, KeyListController *c = nullptr);
    ~Private() override;

    void start();
    void cancel();

    enum UploadStatus {
        Uploaded,
        NotUploaded,
    };

private:
    void ensureDialogCreated();
    void onDialogAccepted();
    void onDialogRejected();

    std::unique_ptr<QGpgME::RevokeKeyJob> startJob();
    void onJobResult(const Error &err);
    void showError(const Error &err);
    void exportFinished(const Error &error, const QByteArray &data);
    void showSuccess(UploadStatus status, const QString &path);

private:
    Key key;
    QPointer<RevokeKeyDialog> dialog;
    QPointer<QGpgME::RevokeKeyJob> job;
    bool upload = false;
};

RevokeKeyCommand::Private *RevokeKeyCommand::d_func()
{
    return static_cast<Private *>(d.get());
}
const RevokeKeyCommand::Private *RevokeKeyCommand::d_func() const
{
    return static_cast<const Private *>(d.get());
}

#define d d_func()
#define q q_func()

RevokeKeyCommand::Private::Private(RevokeKeyCommand *qq, KeyListController *c)
    : Command::Private{qq, c}
{
}

RevokeKeyCommand::Private::~Private() = default;

namespace
{
Key getKey(const std::vector<Key> &keys)
{
    if (keys.size() != 1) {
        qCWarning(KLEOPATRA_LOG) << "Expected exactly one key, but got" << keys.size();
        return {};
    }
    const Key key = keys.front();
    if (key.protocol() != GpgME::OpenPGP) {
        qCWarning(KLEOPATRA_LOG) << "Expected OpenPGP key, but got" << Formatting::displayName(key.protocol()) << "key";
        return {};
    }
    return key;
}
}

void RevokeKeyCommand::Private::start()
{
    key = getKey(keys());
    if (key.isNull()) {
        finished();
        return;
    }

    if (key.isRevoked()) {
        information(i18nc("@info", "This key has already been revoked."));
        finished();
        return;
    }

    ensureDialogCreated();
    Q_ASSERT(dialog);

    dialog->setKey(key);
    dialog->show();
}

void RevokeKeyCommand::Private::cancel()
{
    if (job) {
        job->slotCancel();
    }
    job.clear();
}

void RevokeKeyCommand::Private::ensureDialogCreated()
{
    if (dialog) {
        return;
    }

    dialog = new RevokeKeyDialog;
    applyWindowID(dialog);
    dialog->setAttribute(Qt::WA_DeleteOnClose);

    connect(dialog, &QDialog::accepted, q, [this]() {
        onDialogAccepted();
    });
    connect(dialog, &QDialog::rejected, q, [this]() {
        onDialogRejected();
    });
}

void RevokeKeyCommand::Private::onDialogAccepted()
{
    auto revokeJob = startJob();
    if (!revokeJob) {
        finished();
        return;
    }
    job = revokeJob.release();
}

void RevokeKeyCommand::Private::onDialogRejected()
{
    canceled();
}

namespace
{
std::vector<std::string> toStdStrings(const QStringList &l)
{
    std::vector<std::string> v;
    v.reserve(l.size());
    std::transform(std::begin(l), std::end(l), std::back_inserter(v), std::mem_fn(&QString::toStdString));
    return v;
}

auto descriptionToLines(const QString &description)
{
    std::vector<std::string> lines;
    if (!description.isEmpty()) {
        lines = toStdStrings(description.split(QLatin1Char('\n')));
    }
    return lines;
}
}

std::unique_ptr<QGpgME::RevokeKeyJob> RevokeKeyCommand::Private::startJob()
{
    std::unique_ptr<QGpgME::RevokeKeyJob> revokeJob{QGpgME::openpgp()->revokeKeyJob()};
    Q_ASSERT(revokeJob);

    connect(revokeJob.get(), &QGpgME::RevokeKeyJob::result, q, [this](const GpgME::Error &err) {
        onJobResult(err);
    });
    connect(revokeJob.get(), &QGpgME::Job::jobProgress, q, &Command::progress);

    const auto description = descriptionToLines(dialog->description());
    upload = dialog->uploadToKeyserver();
    const GpgME::Error err = revokeJob->start(key, dialog->reason(), description);
    if (err) {
        showError(err);
        return {};
    }
    Q_EMIT q->info(i18nc("@info:status", "Revoking key..."));

    return revokeJob;
}

void RevokeKeyCommand::Private::onJobResult(const Error &err)
{
    if (err.isCanceled()) {
        finished();
        return;
    }

    if (err) {
        showError(err);
        finished();
        return;
    }

    auto job = QGpgME::openpgp()->publicKeyExportJob(true);
    job->setExportFlags(GPGME_EXPORT_MODE_MINIMAL);

    connect(job, &QGpgME::ExportJob::result, q, [this](const auto &error, const auto &data) {
        exportFinished(error, data);
    });
    job->start({QString::fromLatin1(key.primaryFingerprint())});
}

void RevokeKeyCommand::Private::showError(const Error &err)
{
    error(xi18nc("@info",
                 "<para>An error occurred during the revocation:</para>"
                 "<para><message>%1</message></para>",
                 Formatting::errorAsString(err)),
          i18nc("@title:window", "Revocation Failed"));
}

RevokeKeyCommand::RevokeKeyCommand(QAbstractItemView *v, KeyListController *c)
    : Command{v, new Private{this, c}}
{
}

RevokeKeyCommand::RevokeKeyCommand(const GpgME::Key &key)
    : Command{key, new Private{this}}
{
}

RevokeKeyCommand::~RevokeKeyCommand() = default;

void RevokeKeyCommand::doStart()
{
    d->start();
}

void RevokeKeyCommand::doCancel()
{
    d->cancel();
}

void RevokeKeyCommand::Private::exportFinished(const Error &error, const QByteArray &data)
{
    if (error.isCanceled()) {
        finished();
        return;
    }

    if (error) {
        information(i18nc("@info", "The certificate was revoked successfully."));
        finished();
        return;
    }

    auto name = Formatting::prettyName(key);
    if (name.isEmpty()) {
        name = Formatting::prettyEMail(key);
    }

    auto filename = QStringLiteral("%1_%2_public_revoked.asc").arg(name, Formatting::prettyKeyID(key.keyID()));
    const auto dir = QStandardPaths::writableLocation(QStandardPaths::DocumentsLocation);
    if (QFileInfo::exists(QStringLiteral("%1/%2").arg(dir, filename))) {
        filename = KFileUtils::suggestName(QUrl::fromLocalFile(dir), filename);
    }
    const auto path = QStringLiteral("%1/%2").arg(dir, filename);
    QFile file(path);
    if (!file.open(QIODevice::WriteOnly)) {
        information(i18nc("@info", "The certificate was revoked successfully."));
        finished();
        return;
    }
    file.write(data);
    file.close();

    if (upload) {
        auto const cmd = new Commands::ExportOpenPGPCertsToServerCommand(key);
        cmd->setInteractive(false);
        cmd->start();
        connect(cmd, &Command::finished, q, [cmd, path, this]() {
            if (cmd->success()) {
                showSuccess(Uploaded, path);
            } else {
                showSuccess(NotUploaded, path);
            }
            finished();
        });
    } else {
        showSuccess(NotUploaded, path);
        finished();
    }
}

void RevokeKeyCommand::Private::showSuccess(UploadStatus status, const QString &path)
{
    if (status == Uploaded) {
        if (keyserver().startsWith(QStringLiteral("ldap://")) || keyserver().startsWith(QStringLiteral("ldaps://"))) {
            information(xi18nc("@info",
                               "<para>The certificate was revoked successfully and uploaded to the internal directory.</para><para>The revoked "
                               "certificate was saved to "
                               "<filename>%1</filename>.</para><para>You should send this file to your communication partners with the instruction to import "
                               "it.</para>",
                               path));
        } else {
            information(xi18nc("@info",
                               "<para>The certificate was revoked successfully and uploaded to %1.</para><para>The revoked "
                               "certificate was saved to "
                               "<filename>%2</filename>.</para><para>You should send this file to your communication partners with the instruction to import "
                               "it.</para>",
                               keyserver(),
                               path));
        }
    } else {
        information(xi18nc("@info",
                           "<para>The certificate was revoked successfully.</para><para>The revoked certificate was saved to "
                           "<filename>%1</filename></para><para>You should send this file to your communication partners with the instruction to import "
                           "it.</para>",
                           path));
    }
}

#undef d
#undef q

#include "moc_revokekeycommand.cpp"
