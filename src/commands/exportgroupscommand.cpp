/* -*- mode: c++; c-basic-offset:4 -*-
    exportgroupscommand.cpp

    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2021 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include <config-kleopatra.h>

#include "command_p.h"
#include "exportgroupscommand.h"

#include "utils/filedialog.h"
#include <utils/applicationstate.h>

#include <Libkleo/Algorithm>
#include <Libkleo/Formatting>
#include <Libkleo/KeyGroup>
#include <Libkleo/KeyGroupImportExport>
#include <Libkleo/KeyHelpers>

#include <KLocalizedString>
#include <KSharedConfig>

#include <QGpgME/ExportJob>
#include <QGpgME/Protocol>

#include <QFileInfo>
#include <QStandardPaths>

#include <memory>
#include <vector>

using namespace Kleo;
using namespace GpgME;
using namespace QGpgME;

namespace
{

static const QString certificateGroupFileExtension{QLatin1StringView{".kgrp"}};

QString proposeFilename(const std::vector<KeyGroup> &groups)
{
    QString filename;

    filename = ApplicationState::lastUsedExportDirectory() + QLatin1Char{'/'};
    if (groups.size() == 1) {
        filename += groups.front().name().replace(QLatin1Char{'/'}, QLatin1Char{'_'});
    } else {
        filename += i18nc("A generic filename for exported certificate groups", "certificate groups");
    }

    return filename + certificateGroupFileExtension;
}

QString requestFilename(QWidget *parent, const std::vector<KeyGroup> &groups)
{
    const QString proposedFilename = proposeFilename(groups);

    auto filename =
        FileDialog::getSaveFileNameEx(parent,
                                      i18ncp("@title:window", "Export Certificate Group", "Export Certificate Groups", groups.size()),
                                      QStringLiteral("imp"),
                                      proposedFilename,
                                      i18nc("filename filter like Certificate Groups (*.foo)", "Certificate Groups (*%1)", certificateGroupFileExtension));
    if (!filename.isEmpty()) {
        const QFileInfo fi{filename};
        if (fi.suffix().isEmpty()) {
            filename += certificateGroupFileExtension;
        }
        ApplicationState::setLastUsedExportDirectory(filename);
    }

    return filename;
}

}

class ExportGroupsCommand::Private : public Command::Private
{
    friend class ::ExportGroupsCommand;
    ExportGroupsCommand *q_func() const
    {
        return static_cast<ExportGroupsCommand *>(q);
    }

public:
    explicit Private(ExportGroupsCommand *qq);
    ~Private() override;

    void start();

    bool confirmExport();
    bool exportGroups();
    bool startExportJob(GpgME::Protocol protocol, const std::vector<Key> &keys);

    void onExportJobResult(const QGpgME::Job *job, const GpgME::Error &err, const QByteArray &keyData);

    void cancelJobs();
    void showError(const GpgME::Error &err);

    void finishedIfLastJob(const QGpgME::Job *job);

private:
    std::vector<KeyGroup> groups;
    QString filename;
    std::vector<QPointer<QGpgME::Job>> exportJobs;
};

ExportGroupsCommand::Private *ExportGroupsCommand::d_func()
{
    return static_cast<Private *>(d.get());
}
const ExportGroupsCommand::Private *ExportGroupsCommand::d_func() const
{
    return static_cast<const Private *>(d.get());
}

#define d d_func()
#define q q_func()

ExportGroupsCommand::Private::Private(ExportGroupsCommand *qq)
    : Command::Private(qq)
{
}

ExportGroupsCommand::Private::~Private() = default;

void ExportGroupsCommand::Private::start()
{
    if (groups.empty()) {
        finished();
        return;
    }

    if (!confirmExport()) {
        canceled();
        return;
    }

    filename = requestFilename(parentWidgetOrView(), groups);
    if (filename.isEmpty()) {
        canceled();
        return;
    }

    const auto groupKeys = std::accumulate(std::begin(groups), std::end(groups), KeyGroup::Keys{}, [](auto allKeys, const auto &group) {
        const auto keys = group.keys();
        allKeys.insert(std::begin(keys), std::end(keys));
        return allKeys;
    });
    const auto keys = Kleo::partitionKeysByProtocol(groupKeys);

    // remove/overwrite existing file
    if (QFile::exists(filename) && !QFile::remove(filename)) {
        error(xi18nc("@info", "Cannot overwrite existing <filename>%1</filename>.", filename), i18nc("@title:window", "Export Failed"));
        finished();
        return;
    }
    if (!exportGroups()) {
        finished();
        return;
    }
    if (!keys.openpgp.empty()) {
        if (!startExportJob(GpgME::OpenPGP, keys.openpgp)) {
            finished();
            return;
        }
    }
    if (!keys.cms.empty()) {
        if (!startExportJob(GpgME::CMS, keys.cms)) {
            finishedIfLastJob(nullptr);
        }
    }
}

bool ExportGroupsCommand::Private::confirmExport()
{
    auto notFullyCertifiedGroups = std::accumulate(groups.cbegin(), groups.cend(), QStringList{}, [](auto groupNames, const auto &group) {
        const bool allOpenPGPKeysAreCertifiedByUser = std::ranges::all_of(group.keys(), [](const Key &key) {
            // we only check the primary user ID of OpenPGP keys because currently group certification only certifies the primary user ID
            return key.protocol() != GpgME::OpenPGP || Kleo::userIDIsCertifiedByUser(key.userID(0));
        });
        if (!allOpenPGPKeysAreCertifiedByUser) {
            groupNames.push_back(group.name());
        }
        return groupNames;
    });
    if (!notFullyCertifiedGroups.empty()) {
        if (groups.size() == 1) {
            const auto answer = KMessageBox::warningContinueCancel( //
                parentWidgetOrView(),
                xi18nc("@info",
                       "<para>You haven't certified all OpenPGP certificates in this group "
                       "with an exportable certification. People relying on your certifications "
                       "may not be able to verify the certificates.</para>"
                       "<para>Do you want to continue the export?</para>"),
                i18nc("@title:window", "Confirm Group Export"),
                KGuiItem{i18nc("@action:button", "Export Group")},
                KStandardGuiItem::cancel(),
                QStringLiteral("confirm-export-of-uncertified-groups"));
            return answer == KMessageBox::Continue;
        } else {
            std::sort(notFullyCertifiedGroups.begin(), notFullyCertifiedGroups.end());
            const auto answer = KMessageBox::warningContinueCancelList( //
                parentWidgetOrView(),
                xi18nc("@info",
                       "<para>You haven't certified all OpenPGP certificates in the groups listed below "
                       "with exportable certifications. People relying on your certifications "
                       "may not be able to verify the certificates.</para>"
                       "<para>Do you want to continue the export?</para>"),
                notFullyCertifiedGroups,
                i18nc("@title:window", "Confirm Group Export"),
                KGuiItem{i18nc("@action:button", "Export Groups")},
                KStandardGuiItem::cancel(),
                QStringLiteral("confirm-export-of-uncertified-groups"));
            return answer == KMessageBox::Continue;
        }
    }

    return true;
}

bool ExportGroupsCommand::Private::exportGroups()
{
    const auto result = writeKeyGroups(filename, groups);
    if (result != WriteKeyGroups::Success) {
        error(xi18nc("@info", "Writing groups to file <filename>%1</filename> failed.", filename), i18nc("@title:window", "Export Failed"));
    }
    return result == WriteKeyGroups::Success;
}

bool ExportGroupsCommand::Private::startExportJob(GpgME::Protocol protocol, const std::vector<Key> &keys)
{
    const QGpgME::Protocol *const backend = (protocol == GpgME::OpenPGP) ? QGpgME::openpgp() : QGpgME::smime();
    Q_ASSERT(backend);
    std::unique_ptr<ExportJob> jobOwner(backend->publicKeyExportJob(/*armor=*/true));
    auto job = jobOwner.get();
    Q_ASSERT(job);

    connect(job, &ExportJob::result, q, [this, job](const GpgME::Error &err, const QByteArray &keyData) {
        onExportJobResult(job, err, keyData);
    });
    connect(job, &QGpgME::Job::jobProgress, q, &Command::progress);

    const GpgME::Error err = job->start(Kleo::getFingerprints(keys));
    if (err) {
        showError(err);
        return false;
    }
    Q_EMIT q->info(i18n("Exporting certificate groups..."));

    exportJobs.push_back(jobOwner.release());
    return true;
}

void ExportGroupsCommand::Private::onExportJobResult(const QGpgME::Job *job, const GpgME::Error &err, const QByteArray &keyData)
{
    Q_ASSERT(Kleo::contains(exportJobs, job));

    if (err) {
        showError(err);
        finishedIfLastJob(job);
        return;
    }

    QFile f{filename};
    if (!f.open(QIODevice::WriteOnly | QIODevice::Append)) {
        error(xi18nc("@info", "Cannot open file <filename>%1</filename> for writing.", filename), i18nc("@title:window", "Export Failed"));
        finishedIfLastJob(job);
        return;
    }

    const auto bytesWritten = f.write(keyData);
    if (bytesWritten != keyData.size()) {
        error(xi18nc("@info", "Writing certificates to file <filename>%1</filename> failed.", filename), i18nc("@title:window", "Export Failed"));
    }

    finishedIfLastJob(job);
}

void ExportGroupsCommand::Private::showError(const GpgME::Error &err)
{
    error(xi18nc("@info",
                 "<para>An error occurred during the export:</para>"
                 "<para><message>%1</message></para>",
                 Formatting::errorAsString(err)),
          i18nc("@title:window", "Export Failed"));
}

void ExportGroupsCommand::Private::finishedIfLastJob(const QGpgME::Job *job)
{
    if (job) {
        exportJobs.erase(std::remove(exportJobs.begin(), exportJobs.end(), job), exportJobs.end());
    }
    if (exportJobs.size() == 0) {
        finished();
    }
}

void ExportGroupsCommand::Private::cancelJobs()
{
    std::for_each(std::cbegin(exportJobs), std::cend(exportJobs), [](const auto &job) {
        if (job) {
            job->slotCancel();
        }
    });
    exportJobs.clear();
}

ExportGroupsCommand::ExportGroupsCommand(const std::vector<KeyGroup> &groups)
    : Command{new Private{this}}
{
    d->groups = groups;
}

ExportGroupsCommand::~ExportGroupsCommand() = default;

void ExportGroupsCommand::doStart()
{
    d->start();
}

void ExportGroupsCommand::doCancel()
{
    d->cancelJobs();
}

#undef d
#undef q

#include "moc_exportgroupscommand.cpp"
