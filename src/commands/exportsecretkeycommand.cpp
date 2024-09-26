/* -*- mode: c++; c-basic-offset:4 -*-
    commands/exportsecretkeycommand.cpp

    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2022 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include <config-kleopatra.h>

#include "command_p.h"
#include "exportsecretkeycommand.h"

#include "fileoperationspreferences.h"
#include "utils/filedialog.h"
#include <utils/applicationstate.h>

#include <Libkleo/Classify>
#include <Libkleo/Formatting>

#include <KLocalizedString>
#include <KSharedConfig>

#include <QGpgME/ExportJob>
#include <QGpgME/Protocol>

#include <QFileInfo>
#include <QStandardPaths>

#include <gpgme++/context.h>

#include <algorithm>
#include <memory>
#include <vector>

#include <kleopatra_debug.h>

using namespace Kleo;
using namespace Kleo::Commands;
using namespace GpgME;

namespace
{

QString openPGPCertificateFileExtension()
{
    return outputFileExtension(Class::OpenPGP | Class::Ascii | Class::Certificate, FileOperationsPreferences().usePGPFileExt());
}

QString cmsCertificateFileExtension()
{
    return outputFileExtension(Class::CMS | Class::Binary | Class::ExportedPSM,
                               /*usePGPFileExt=*/false);
}

QString certificateFileExtension(GpgME::Protocol protocol)
{
    switch (protocol) {
    case GpgME::OpenPGP:
        return openPGPCertificateFileExtension();
    case GpgME::CMS:
        return cmsCertificateFileExtension();
    default:
        qCWarning(KLEOPATRA_LOG) << __func__ << "Error: Unknown protocol" << protocol;
        return QStringLiteral("txt");
    }
}

QString proposeFilename(const Key &key)
{
    QString filename;

    auto name = Formatting::prettyName(key);
    if (name.isEmpty()) {
        name = Formatting::prettyEMail(key);
    }
    const auto keyID = Formatting::prettyKeyID(key.keyID());
    /* Not translated so it's better to use in tutorials etc. */
    filename = QStringView{u"%1_%2_SECRET"}.arg(name, keyID);
    filename.replace(u'/', u'_');

    return ApplicationState::lastUsedExportDirectory() + u'/' + filename + u'.' + certificateFileExtension(key.protocol());
}

QString secretKeyFileFilters(GpgME::Protocol protocol)
{
    switch (protocol) {
    case GpgME::OpenPGP:
        return i18nc("description of filename filter", "Secret Key Files") + QLatin1StringView{" (*.asc *.gpg *.pgp)"};
    case GpgME::CMS:
        return i18nc("description of filename filter", "Secret Key Files") + QLatin1StringView{" (*.p12)"};
    default:
        qCWarning(KLEOPATRA_LOG) << __func__ << "Error: Unknown protocol" << protocol;
        return i18nc("description of filename filter", "All Files") + QLatin1StringView{" (*)"};
    }
}

QString requestFilename(const Key &key, const QString &proposedFilename, QWidget *parent)
{
    auto filename = FileDialog::getSaveFileNameEx(parent,
                                                  i18nc("@title:window", "Secret Key Backup"),
                                                  QStringLiteral("imp"),
                                                  proposedFilename,
                                                  secretKeyFileFilters(key.protocol()));

    if (!filename.isEmpty()) {
        const QFileInfo fi{filename};
        if (fi.suffix().isEmpty()) {
            filename += u'.' + certificateFileExtension(key.protocol());
        }
        ApplicationState::setLastUsedExportDirectory(filename);
    }

    return filename;
}

QString errorCaption()
{
    return i18nc("@title:window", "Secret Key Backup Error");
}

}

class ExportSecretKeyCommand::Private : public Command::Private
{
    friend class ::ExportSecretKeyCommand;
    ExportSecretKeyCommand *q_func() const
    {
        return static_cast<ExportSecretKeyCommand *>(q);
    }

public:
    explicit Private(ExportSecretKeyCommand *qq, KeyListController *c = nullptr);
    ~Private() override;

    void start();
    void cancel();

private:
    std::unique_ptr<QGpgME::ExportJob> startExportJob(const Key &key);
    void onExportJobResult(const Error &err, const QByteArray &keyData);
    void showError(const Error &err);

private:
    QString filename;
    QPointer<QGpgME::ExportJob> job;
    bool interactive = true;
    bool success = false;
};

ExportSecretKeyCommand::Private *ExportSecretKeyCommand::d_func()
{
    return static_cast<Private *>(d.get());
}
const ExportSecretKeyCommand::Private *ExportSecretKeyCommand::d_func() const
{
    return static_cast<const Private *>(d.get());
}

#define d d_func()
#define q q_func()

ExportSecretKeyCommand::Private::Private(ExportSecretKeyCommand *qq, KeyListController *c)
    : Command::Private{qq, c}
{
}

ExportSecretKeyCommand::Private::~Private() = default;

void ExportSecretKeyCommand::Private::start()
{
    const Key key = this->key();

    if (key.isNull()) {
        finished();
        return;
    }

    if (filename.isEmpty()) {
        filename = requestFilename(key, proposeFilename(key), parentWidgetOrView());
    }
    if (filename.isEmpty()) {
        canceled();
        return;
    }

    auto exportJob = startExportJob(key);
    if (!exportJob) {
        finished();
        return;
    }
    job = exportJob.release();
}

void ExportSecretKeyCommand::Private::cancel()
{
    if (job) {
        job->slotCancel();
    }
    job.clear();
}

std::unique_ptr<QGpgME::ExportJob> ExportSecretKeyCommand::Private::startExportJob(const Key &key)
{
    const bool armor = key.protocol() == GpgME::OpenPGP && filename.endsWith(u".asc", Qt::CaseInsensitive);
    const QGpgME::Protocol *const backend = (key.protocol() == GpgME::OpenPGP) ? QGpgME::openpgp() : QGpgME::smime();
    Q_ASSERT(backend);
    std::unique_ptr<QGpgME::ExportJob> exportJob{backend->secretKeyExportJob(armor)};
    Q_ASSERT(exportJob);

    if (key.protocol() == GpgME::CMS) {
        exportJob->setExportFlags(GpgME::Context::ExportPKCS12);
    }

    connect(exportJob.get(), &QGpgME::ExportJob::result, q, [this](const GpgME::Error &err, const QByteArray &keyData) {
        onExportJobResult(err, keyData);
    });
    connect(exportJob.get(), &QGpgME::Job::jobProgress, q, &Command::progress);

    const GpgME::Error err = exportJob->start({QLatin1StringView{key.primaryFingerprint()}});
    if (err) {
        showError(err);
        return {};
    }
    Q_EMIT q->info(i18nc("@info:status", "Backing up secret key..."));

    return exportJob;
}

void ExportSecretKeyCommand::Private::onExportJobResult(const Error &err, const QByteArray &keyData)
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

    if (keyData.isEmpty()) {
        error(i18nc("@info", "The result of the backup is empty. Maybe you entered an empty or a wrong passphrase."), errorCaption());
        finished();
        return;
    }

    QFile f{filename};
    if (!f.open(QIODevice::WriteOnly)) {
        error(xi18nc("@info", "Cannot open file <filename>%1</filename> for writing.", filename), errorCaption());
        finished();
        return;
    }

    const auto bytesWritten = f.write(keyData);
    if (bytesWritten != keyData.size()) {
        error(xi18nc("@info", "Writing key to file <filename>%1</filename> failed.", filename), errorCaption());
        finished();
        return;
    }

    if (interactive) {
        information(i18nc("@info", "The backup of the secret key was created successfully."), i18nc("@title:window", "Secret Key Backup"));
    }

    success = true;
    finished();
}

void ExportSecretKeyCommand::Private::showError(const Error &err)
{
    error(xi18nc("@info",
                 "<para>An error occurred during the backup of the secret key:</para>"
                 "<para><message>%1</message></para>",
                 Formatting::errorAsString(err)),
          errorCaption());
}

ExportSecretKeyCommand::ExportSecretKeyCommand(QAbstractItemView *view, KeyListController *controller)
    : Command{view, new Private{this, controller}}
{
}

ExportSecretKeyCommand::ExportSecretKeyCommand(const GpgME::Key &key)
    : Command{key, new Private{this}}
{
}

ExportSecretKeyCommand::~ExportSecretKeyCommand() = default;

void ExportSecretKeyCommand::doStart()
{
    d->start();
}

void ExportSecretKeyCommand::doCancel()
{
    d->cancel();
}

void ExportSecretKeyCommand::setInteractive(bool interactive)
{
    d->interactive = interactive;
}

void ExportSecretKeyCommand::setFileName(const QString &fileName)
{
    d->filename = fileName;
}

bool ExportSecretKeyCommand::success() const
{
    return d->success;
}

#undef d
#undef q

#include "moc_exportsecretkeycommand.cpp"
