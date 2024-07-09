/* -*- mode: c++; c-basic-offset:4 -*-
    commands/importcertificatescommand_p.h

    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2007, 2008 Klarälvdalens Datakonsult AB
    SPDX-FileCopyrightText: 2021, 2022 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#pragma once

#include "command_p.h"
#include "importcertificatescommand.h"

#include <Libkleo/AuditLogEntry>
#include <Libkleo/KeyGroup>

#include <gpgme++/global.h>
#include <gpgme++/importresult.h>

#include <map>
#include <queue>
#include <vector>

namespace GpgME
{
class Import;
class KeyListResult;
class Error;
}

namespace QGpgME
{
class Job;
}

namespace Kleo
{
class KeyCacheAutoRefreshSuspension;
}

class QByteArray;
class QProgressDialog;

enum class ImportType {
    Unknown,
    Local,
    External,
};

struct ImportJobData {
    QString id;
    GpgME::Protocol protocol = GpgME::UnknownProtocol;
    ImportType type = ImportType::Unknown;
    QGpgME::Job *job = nullptr;
    std::vector<QMetaObject::Connection> connections;
};

bool operator==(const ImportJobData &lhs, const ImportJobData &rhs);

struct ImportResultData {
    QString id;
    GpgME::Protocol protocol = GpgME::UnknownProtocol;
    ImportType type = ImportType::Unknown;
    GpgME::ImportResult result;
    Kleo::AuditLogEntry auditLog;
};

struct ImportedGroup {
    enum class Status {
        New,
        Updated,
    };
    QString id;
    Kleo::KeyGroup group;
    Status status;
};

struct ImportOptions {
    QString importFilter;
    QStringList importOptions;
    GpgME::Key::Origin keyOrigin = GpgME::Key::OriginUnknown;
    QString keyOriginUrl;
};

class Kleo::ImportCertificatesCommand::Private : public Command::Private
{
    friend class ::Kleo::ImportCertificatesCommand;
    Kleo::ImportCertificatesCommand *q_func() const
    {
        return static_cast<ImportCertificatesCommand *>(q);
    }

public:
    explicit Private(ImportCertificatesCommand *qq, KeyListController *c);
    ~Private() override;

    void setWaitForMoreJobs(bool waiting);
    void setProgressWindowTitle(const QString &title);
    void setProgressLabelText(const QString &text);

    void startImport(GpgME::Protocol proto, const QByteArray &data, const QString &id = QString(), const ImportOptions &options = {});
    void startImport(GpgME::Protocol proto, const std::vector<GpgME::Key> &keys, const QString &id = QString());
    void startImport(GpgME::Protocol proto, const QStringList &keyIds, const QString &id = {});
    void onImportResult(const GpgME::ImportResult &, QGpgME::Job *job = nullptr);
    void addImportResult(const ImportResultData &result, const ImportJobData &job = ImportJobData{});

    void importGroupsFromFile(const QString &filename);

    void showError(const ImportResultData &result);

    void setImportResultProxyModel(const std::vector<ImportResultData> &results);

    bool showPleaseCertify(const GpgME::Import &imp);

    void keyListDone(const GpgME::KeyListResult &result, const std::vector<GpgME::Key> &keys, const QString &, const GpgME::Error &);

private:
    void showDetails(const std::vector<ImportResultData> &results, const std::vector<ImportedGroup> &groups);
    void processResults();
    void tryToFinish();
    void keyCacheUpdated();
    void importGroups();
    std::set<QString> getMissingSignerKeyIds(const std::vector<ImportResultData> &results);
    void importSignerKeys(const std::set<QString> &keyIds);

    void setUpProgressDialog();
    void increaseProgressMaximum();
    void increaseProgressValue();
    void setProgressToMaximum();

private:
    bool waitForMoreJobs = false;
    bool importingSignerKeys = false;
    bool certificateListWasEmpty = false;
    std::vector<GpgME::Protocol> nonWorkingProtocols;
    std::queue<ImportJobData> pendingJobs;
    std::vector<ImportJobData> runningJobs;
    std::vector<QString> filesToImportGroupsFrom;
    std::vector<ImportResultData> results;
    std::vector<ImportedGroup> importedGroups;
    std::shared_ptr<KeyCacheAutoRefreshSuspension> keyCacheAutoRefreshSuspension;
    QMetaObject::Connection keyListConnection;

    QString progressWindowTitle;
    QString progressLabelText;
    QPointer<QProgressDialog> progressDialog;
};

inline Kleo::ImportCertificatesCommand::Private *Kleo::ImportCertificatesCommand::d_func()
{
    return static_cast<Private *>(d.get());
}
inline const Kleo::ImportCertificatesCommand::Private *Kleo::ImportCertificatesCommand::d_func() const
{
    return static_cast<const Private *>(d.get());
}

inline Kleo::ImportCertificatesCommand::ImportCertificatesCommand(Private *pp)
    : Command(pp)
{
}
inline Kleo::ImportCertificatesCommand::ImportCertificatesCommand(QAbstractItemView *v, Private *pp)
    : Command(v, pp)
{
}
