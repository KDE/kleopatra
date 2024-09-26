/* -*- mode: c++; c-basic-offset:4 -*-
    commands/exportsecretsubkeycommand.cpp

    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2022 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include <config-kleopatra.h>

#include "command_p.h"
#include "exportsecretsubkeycommand.h"

#include "fileoperationspreferences.h"
#include <utils/applicationstate.h>
#include <utils/filedialog.h>

#include <Libkleo/Classify>
#include <Libkleo/Formatting>

#include <KLocalizedString>
#include <KSharedConfig>

#include <QGpgME/ExportJob>
#include <QGpgME/Protocol>

#include <QFileInfo>
#include <QStandardPaths>

#include <algorithm>
#include <memory>
#include <vector>

using namespace Kleo;
using namespace GpgME;

namespace
{

QString openPGPCertificateFileExtension()
{
    return outputFileExtension(Class::OpenPGP | Class::Ascii | Class::Certificate, FileOperationsPreferences().usePGPFileExt());
}

QString proposeFilename(const std::vector<Subkey> &subkeys)
{
    QString filename;

    if (subkeys.size() == 1) {
        const auto subkey = subkeys.front();
        const auto key = subkey.parent();
        auto name = Formatting::prettyName(key);
        if (name.isEmpty()) {
            name = Formatting::prettyEMail(key);
        }
        const auto keyID = Formatting::prettyKeyID(key.keyID());
        const auto subkeyID = Formatting::prettyKeyID(subkey.keyID());
        const auto usage = Formatting::usageString(subkey).replace(QLatin1StringView{", "}, QLatin1StringView{"_"});
        /* Not translated so it's better to use in tutorials etc. */
        filename = QStringView{u"%1_%2_SECRET_SUBKEY_%3_%4"}.arg(name, keyID, subkeyID, usage);
    } else {
        filename = i18nc("Generic filename for exported subkeys", "subkeys");
    }
    filename.replace(u'/', u'_');

    return ApplicationState::lastUsedExportDirectory() + u'/' + filename + u'.' + openPGPCertificateFileExtension();
}

QString requestFilename(const std::vector<Subkey> &subkeys, const QString &proposedFilename, QWidget *parent)
{
    auto filename = FileDialog::getSaveFileNameEx(parent,
                                                  i18ncp("@title:window", "Export Subkey", "Export Subkeys", subkeys.size()),
                                                  QStringLiteral("imp"),
                                                  proposedFilename,
                                                  i18nc("description of filename filter", "Secret Key Files") + QLatin1StringView{" (*.asc *.gpg *.pgp)"});

    if (!filename.isEmpty()) {
        const QFileInfo fi{filename};
        if (fi.suffix().isEmpty()) {
            filename += u'.' + openPGPCertificateFileExtension();
        }
        ApplicationState::setLastUsedExportDirectory(filename);
    }

    return filename;
}

template<typename SubkeyContainer>
QStringList getSubkeyFingerprints(const SubkeyContainer &subkeys)
{
    QStringList fingerprints;

    fingerprints.reserve(subkeys.size());
    std::transform(std::begin(subkeys), std::end(subkeys), std::back_inserter(fingerprints), [](const auto &subkey) {
        return QLatin1StringView{subkey.fingerprint()} + u'!';
    });

    return fingerprints;
}
}

class ExportSecretSubkeyCommand::Private : public Command::Private
{
    friend class ::ExportSecretSubkeyCommand;
    ExportSecretSubkeyCommand *q_func() const
    {
        return static_cast<ExportSecretSubkeyCommand *>(q);
    }

public:
    explicit Private(ExportSecretSubkeyCommand *qq);
    ~Private() override;

    void start();
    void cancel();

private:
    std::unique_ptr<QGpgME::ExportJob> startExportJob(const std::vector<Subkey> &subkeys);
    void onExportJobResult(const Error &err, const QByteArray &keyData);
    void showError(const Error &err);

private:
    std::vector<Subkey> subkeys;
    QString filename;
    QPointer<QGpgME::ExportJob> job;
};

ExportSecretSubkeyCommand::Private *ExportSecretSubkeyCommand::d_func()
{
    return static_cast<Private *>(d.get());
}
const ExportSecretSubkeyCommand::Private *ExportSecretSubkeyCommand::d_func() const
{
    return static_cast<const Private *>(d.get());
}

#define d d_func()
#define q q_func()

ExportSecretSubkeyCommand::Private::Private(ExportSecretSubkeyCommand *qq)
    : Command::Private{qq}
{
}

ExportSecretSubkeyCommand::Private::~Private() = default;

void ExportSecretSubkeyCommand::Private::start()
{
    if (subkeys.empty()) {
        finished();
        return;
    }

    filename = requestFilename(subkeys, proposeFilename(subkeys), parentWidgetOrView());
    if (filename.isEmpty()) {
        canceled();
        return;
    }

    auto exportJob = startExportJob(subkeys);
    if (!exportJob) {
        finished();
        return;
    }
    job = exportJob.release();
}

void ExportSecretSubkeyCommand::Private::cancel()
{
    if (job) {
        job->slotCancel();
    }
    job.clear();
}

std::unique_ptr<QGpgME::ExportJob> ExportSecretSubkeyCommand::Private::startExportJob(const std::vector<Subkey> &subkeys)
{
    const bool armor = filename.endsWith(u".asc", Qt::CaseInsensitive);
    std::unique_ptr<QGpgME::ExportJob> exportJob{QGpgME::openpgp()->secretSubkeyExportJob(armor)};
    Q_ASSERT(exportJob);

    connect(exportJob.get(), &QGpgME::ExportJob::result, q, [this](const GpgME::Error &err, const QByteArray &keyData) {
        onExportJobResult(err, keyData);
    });
    connect(exportJob.get(), &QGpgME::Job::jobProgress, q, &Command::progress);

    const GpgME::Error err = exportJob->start(getSubkeyFingerprints(subkeys));
    if (err) {
        showError(err);
        return {};
    }
    Q_EMIT q->info(i18nc("@info:status", "Exporting subkeys..."));

    return exportJob;
}

void ExportSecretSubkeyCommand::Private::onExportJobResult(const Error &err, const QByteArray &keyData)
{
    if (err) {
        showError(err);
        finished();
        return;
    }

    if (err.isCanceled()) {
        finished();
        return;
    }

    if (keyData.isEmpty()) {
        error(i18nc("@info", "The result of the export is empty."), i18nc("@title:window", "Export Failed"));
        finished();
        return;
    }

    QFile f{filename};
    if (!f.open(QIODevice::WriteOnly)) {
        error(xi18nc("@info", "Cannot open file <filename>%1</filename> for writing.", filename), i18nc("@title:window", "Export Failed"));
        finished();
        return;
    }

    const auto bytesWritten = f.write(keyData);
    if (bytesWritten != keyData.size()) {
        error(xi18ncp("@info",
                      "Writing subkey to file <filename>%2</filename> failed.",
                      "Writing subkeys to file <filename>%2</filename> failed.",
                      subkeys.size(),
                      filename),
              i18nc("@title:window", "Export Failed"));
        finished();
        return;
    }

    information(i18ncp("@info", "The subkey was exported successfully.", "%1 subkeys were exported successfully.", subkeys.size()),
                i18nc("@title:window", "Secret Key Backup"));
    finished();
}

void ExportSecretSubkeyCommand::Private::showError(const Error &err)
{
    error(xi18nc("@info",
                 "<para>An error occurred during the export:</para>"
                 "<para><message>%1</message></para>",
                 Formatting::errorAsString(err)),
          i18nc("@title:window", "Export Failed"));
}

ExportSecretSubkeyCommand::ExportSecretSubkeyCommand(const std::vector<GpgME::Subkey> &subkeys)
    : Command{new Private{this}}
{
    d->subkeys = subkeys;
}

ExportSecretSubkeyCommand::~ExportSecretSubkeyCommand() = default;

void ExportSecretSubkeyCommand::doStart()
{
    d->start();
}

void ExportSecretSubkeyCommand::doCancel()
{
    d->cancel();
}

#undef d
#undef q

#include "moc_exportsecretsubkeycommand.cpp"
