/* -*- mode: c++; c-basic-offset:4 -*-
    commands/importcertificatescommand.cpp

    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2007, 2008 Klarälvdalens Datakonsult AB
    SPDX-FileCopyrightText: 2016 Bundesamt für Sicherheit in der Informationstechnik
    SPDX-FileContributor: Intevation GmbH
    SPDX-FileCopyrightText: 2021, 2022 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include <config-kleopatra.h>

#include "importcertificatescommand.h"
#include "importcertificatescommand_p.h"

#include "certifycertificatecommand.h"
#include "kleopatra_debug.h"
#include <settings.h>
#include <utils/memory-helpers.h>

#include <Libkleo/Algorithm>
#include <Libkleo/Compat>
#include <Libkleo/Formatting>
#include <Libkleo/KeyCache>
#include <Libkleo/KeyGroupImportExport>
#include <Libkleo/KeyHelpers>
#include <Libkleo/KeyList>
#include <Libkleo/KeyListSortFilterProxyModel>
#include <Libkleo/MessageBox>
#include <Libkleo/Predicates>
#include <Libkleo/Stl_Util>

#include <QGpgME/ChangeOwnerTrustJob>
#include <QGpgME/ImportFromKeyserverJob>
#include <QGpgME/ImportJob>
#include <QGpgME/Protocol>
#include <QGpgME/ReceiveKeysJob>

#include <gpgme++/context.h>
#include <gpgme++/global.h>
#include <gpgme++/importresult.h>
#include <gpgme++/key.h>
#include <gpgme++/keylistresult.h>

#include <KLocalizedString>
#include <KMessageBox>

#include <QByteArray>
#include <QEventLoop>
#include <QProgressDialog>
#include <QString>
#include <QTreeView>
#include <QWidget>

#include <algorithm>
#include <map>
#include <memory>
#include <set>
#include <unordered_set>

using namespace GpgME;
using namespace Kleo;
using namespace QGpgME;

static void disconnectConnection(const QMetaObject::Connection &connection)
{
    // trivial function for disconnecting a signal-slot connection
    QObject::disconnect(connection);
}

bool operator==(const ImportJobData &lhs, const ImportJobData &rhs)
{
    return lhs.job == rhs.job;
}

namespace
{

make_comparator_str(ByImportFingerprint, .fingerprint());

class ImportResultProxyModel : public AbstractKeyListSortFilterProxyModel
{
    Q_OBJECT
public:
    ImportResultProxyModel(const std::vector<ImportResultData> &results, QObject *parent = nullptr)
        : AbstractKeyListSortFilterProxyModel(parent)
    {
        updateFindCache(results);
    }

    ~ImportResultProxyModel() override
    {
    }

    ImportResultProxyModel *clone() const override
    {
        // compiler-generated copy ctor is fine!
        return new ImportResultProxyModel(*this);
    }

    void setImportResults(const std::vector<ImportResultData> &results)
    {
        updateFindCache(results);
        invalidateFilter();
    }

protected:
    QVariant data(const QModelIndex &index, int role) const override
    {
        if (!index.isValid() || role != Qt::ToolTipRole) {
            return AbstractKeyListSortFilterProxyModel::data(index, role);
        }
        const QString fpr = index.data(KeyList::FingerprintRole).toString();
        // find information:
        const std::vector<Import>::const_iterator it =
            Kleo::binary_find(m_importsByFingerprint.begin(), m_importsByFingerprint.end(), fpr.toLatin1().constData(), ByImportFingerprint<std::less>());
        if (it == m_importsByFingerprint.end()) {
            return AbstractKeyListSortFilterProxyModel::data(index, role);
        } else {
            QStringList rv;
            const auto ids = m_idsByFingerprint[it->fingerprint()];
            rv.reserve(ids.size());
            std::copy(ids.cbegin(), ids.cend(), std::back_inserter(rv));
            return Formatting::importMetaData(*it, rv);
        }
    }
    bool filterAcceptsRow(int source_row, const QModelIndex &source_parent) const override
    {
        //
        // 0. Keep parents of matching children:
        //
        const QModelIndex index = sourceModel()->index(source_row, 0, source_parent);
        Q_ASSERT(index.isValid());
        for (int i = 0, end = sourceModel()->rowCount(index); i != end; ++i)
            if (filterAcceptsRow(i, index)) {
                return true;
            }
        //
        // 1. Check that this is an imported key:
        //
        const QString fpr = index.data(KeyList::FingerprintRole).toString();

        return std::binary_search(m_importsByFingerprint.begin(), m_importsByFingerprint.end(), fpr.toLatin1().constData(), ByImportFingerprint<std::less>());
    }

private:
    void updateFindCache(const std::vector<ImportResultData> &results)
    {
        m_importsByFingerprint.clear();
        m_idsByFingerprint.clear();
        m_results = results;
        for (const auto &r : results) {
            const std::vector<Import> imports = r.result.imports();
            m_importsByFingerprint.insert(m_importsByFingerprint.end(), imports.begin(), imports.end());
            for (std::vector<Import>::const_iterator it = imports.begin(), end = imports.end(); it != end; ++it) {
                m_idsByFingerprint[it->fingerprint()].insert(r.id);
            }
        }
        std::sort(m_importsByFingerprint.begin(), m_importsByFingerprint.end(), ByImportFingerprint<std::less>());
    }

private:
    mutable std::vector<Import> m_importsByFingerprint;
    mutable std::map<const char *, std::set<QString>, ByImportFingerprint<std::less>> m_idsByFingerprint;
    std::vector<ImportResultData> m_results;
};

bool importFailed(const ImportResultData &r)
{
    // ignore GPG_ERR_EOF error to handle the "failed" import of files
    // without X.509 certificates by gpgsm gracefully
    return r.result.error() && r.result.error().code() != GPG_ERR_EOF;
}

bool importWasCanceled(const ImportResultData &r)
{
    return r.result.error().isCanceled();
}

}

ImportCertificatesCommand::Private::Private(ImportCertificatesCommand *qq, KeyListController *c)
    : Command::Private(qq, c)
    , certificateListWasEmpty(KeyCache::instance()->keys().empty())
    , progressWindowTitle{i18nc("@title:window", "Importing Certificates")}
    , progressLabelText{i18n("Importing certificates... (this can take a while)")}
{
}

ImportCertificatesCommand::Private::~Private()
{
    if (progressDialog) {
        delete progressDialog;
    }
}

#define d d_func()
#define q q_func()

ImportCertificatesCommand::ImportCertificatesCommand(KeyListController *p)
    : Command(new Private(this, p))
{
}

ImportCertificatesCommand::ImportCertificatesCommand(QAbstractItemView *v, KeyListController *p)
    : Command(v, new Private(this, p))
{
}

ImportCertificatesCommand::~ImportCertificatesCommand() = default;

static QString format_ids(const std::vector<QString> &ids)
{
    QStringList escapedIds;
    for (const QString &id : ids) {
        if (!id.isEmpty()) {
            escapedIds << id.toHtmlEscaped();
        }
    }
    return escapedIds.join(QLatin1StringView("<br>"));
}

static QString make_tooltip(const std::vector<ImportResultData> &results)
{
    if (results.empty()) {
        return {};
    }

    std::vector<QString> ids;
    ids.reserve(results.size());
    std::transform(std::begin(results), std::end(results), std::back_inserter(ids), [](const auto &r) {
        return r.id;
    });
    std::sort(std::begin(ids), std::end(ids));
    ids.erase(std::unique(std::begin(ids), std::end(ids)), std::end(ids));

    if (ids.size() == 1)
        if (ids.front().isEmpty()) {
            return {};
        } else
            return i18nc("@info:tooltip", "Imported Certificates from %1", ids.front().toHtmlEscaped());
    else
        return i18nc("@info:tooltip", "Imported certificates from these sources:<br/>%1", format_ids(ids));
}

void ImportCertificatesCommand::Private::setImportResultProxyModel(const std::vector<ImportResultData> &results)
{
    if (std::none_of(std::begin(results), std::end(results), [](const auto &r) {
            return r.result.numConsidered() > 0;
        })) {
        return;
    }

    if (certificateListWasEmpty) {
        return;
    }

    q->addTemporaryView(i18nc("@title:tab", "Imported Certificates"), new ImportResultProxyModel(results), make_tooltip(results));
    if (QTreeView *const tv = qobject_cast<QTreeView *>(parentWidgetOrView())) {
        tv->expandAll();
    }
}

int sum(const std::vector<ImportResult> &res, int (ImportResult::*fun)() const)
{
    return kdtools::accumulate_transform(res.begin(), res.end(), std::mem_fn(fun), 0);
}

static QString make_report(const std::vector<ImportResultData> &results, const std::vector<ImportedGroup> &groups)
{
    const KLocalizedString normalLine = ki18n("<tr><td align=\"right\">%1</td><td>%2</td></tr>");
    const KLocalizedString boldLine = ki18n("<tr><td align=\"right\"><b>%1</b></td><td>%2</td></tr>");
    const KLocalizedString headerLine = ki18n("<tr><th colspan=\"2\" align=\"center\">%1</th></tr>");

    std::vector<ImportResult> res;
    res.reserve(results.size());
    std::transform(std::begin(results), std::end(results), std::back_inserter(res), [](const auto &r) {
        return r.result;
    });

    const auto numProcessedCertificates = sum(res, &ImportResult::numConsidered);

    QStringList lines;

    if (numProcessedCertificates > 0 || groups.size() == 0) {
        lines.push_back(headerLine.subs(i18n("Certificates")).toString());
        lines.push_back(normalLine.subs(i18n("Total number processed:")).subs(numProcessedCertificates).toString());
        lines.push_back(normalLine.subs(i18n("Imported:")).subs(sum(res, &ImportResult::numImported)).toString());
        if (const int n = sum(res, &ImportResult::newSignatures))
            lines.push_back(normalLine.subs(i18n("New signatures:")).subs(n).toString());
        if (const int n = sum(res, &ImportResult::newUserIDs))
            lines.push_back(normalLine.subs(i18n("New user IDs:")).subs(n).toString());
        if (const int n = sum(res, &ImportResult::numKeysWithoutUserID))
            lines.push_back(normalLine.subs(i18n("Certificates without user IDs:")).subs(n).toString());
        if (const int n = sum(res, &ImportResult::newSubkeys))
            lines.push_back(normalLine.subs(i18n("New subkeys:")).subs(n).toString());
        if (const int n = sum(res, &ImportResult::newRevocations))
            lines.push_back(boldLine.subs(i18n("Newly revoked:")).subs(n).toString());
        if (const int n = sum(res, &ImportResult::notImported))
            lines.push_back(boldLine.subs(i18n("Not imported:")).subs(n).toString());
        if (const int n = sum(res, &ImportResult::numUnchanged))
            lines.push_back(normalLine.subs(i18n("Unchanged:")).subs(n).toString());
        if (const int n = sum(res, &ImportResult::numSecretKeysConsidered))
            lines.push_back(normalLine.subs(i18n("Secret keys processed:")).subs(n).toString());
        if (const int n = sum(res, &ImportResult::numSecretKeysImported))
            lines.push_back(normalLine.subs(i18n("Secret keys imported:")).subs(n).toString());
        if (const int n = sum(res, &ImportResult::numSecretKeysConsidered) - sum(res, &ImportResult::numSecretKeysImported)
                - sum(res, &ImportResult::numSecretKeysUnchanged))
            if (n > 0)
                lines.push_back(boldLine.subs(i18n("Secret keys <em>not</em> imported:")).subs(n).toString());
        if (const int n = sum(res, &ImportResult::numSecretKeysUnchanged))
            lines.push_back(normalLine.subs(i18n("Secret keys unchanged:")).subs(n).toString());
        if (const int n = sum(res, &ImportResult::numV3KeysSkipped))
            lines.push_back(normalLine.subs(i18n("Deprecated PGP-2 keys skipped:")).subs(n).toString());
    }

    if (!lines.empty()) {
        lines.push_back(headerLine.subs(QLatin1StringView{"&nbsp;"}).toString());
    }

    if (groups.size() > 0) {
        const auto newGroups = std::count_if(std::begin(groups), std::end(groups), [](const auto &g) {
            return g.status == ImportedGroup::Status::New;
        });
        const auto updatedGroups = groups.size() - newGroups;
        lines.push_back(headerLine.subs(i18n("Certificate Groups")).toString());
        lines.push_back(normalLine.subs(i18n("Total number processed:")).subs(groups.size()).toString());
        lines.push_back(normalLine.subs(i18n("New groups:")).subs(newGroups).toString());
        lines.push_back(normalLine.subs(i18n("Updated groups:")).subs(updatedGroups).toString());
    }

    return lines.join(QLatin1StringView{});
}

static bool isImportFromSingleSource(const std::vector<ImportResultData> &res)
{
    return (res.size() == 1) || (res.size() == 2 && res[0].id == res[1].id);
}

static QString make_message_report(const std::vector<ImportResultData> &res, const std::vector<ImportedGroup> &groups)
{
    QString report{QLatin1StringView{"<html>"}};
    if (res.empty()) {
        report += i18n("No imports (should not happen, please report a bug).");
    } else {
        const QString title = isImportFromSingleSource(res) && !res.front().id.isEmpty() ? i18n("Detailed results of importing %1:", res.front().id)
                                                                                         : i18n("Detailed results of import:");
        report += QLatin1StringView{"<p>"} + title + QLatin1StringView{"</p>"};
        report += QLatin1StringView{"<p><table width=\"100%\">"};
        report += make_report(res, groups);
        report += QLatin1StringView{"</table></p>"};
    }
    report += QLatin1StringView{"</html>"};
    return report;
}

// Returns false on error, true if please certify was shown.
bool ImportCertificatesCommand::Private::showPleaseCertify(const GpgME::Import &imp)
{
    if (!Kleo::userHasCertificationKey()) {
        qCDebug(KLEOPATRA_LOG) << q << __func__ << "No certification key available";
        return false;
    }

    const char *fpr = imp.fingerprint();
    if (!fpr) {
        // WTF
        qCWarning(KLEOPATRA_LOG) << "Import without fingerprint";
        return false;
    }
    // Exactly one public key imported. Let's see if it is openpgp. We are async here so
    // we can just fetch it.

    auto ctx = wrap_unique(GpgME::Context::createForProtocol(GpgME::OpenPGP));
    if (!ctx) {
        // WTF
        qCWarning(KLEOPATRA_LOG) << "Failed to create OpenPGP proto";
        return false;
    }
    ctx->addKeyListMode(KeyListMode::WithSecret);
    GpgME::Error err;
    const auto key = ctx->key(fpr, err, false);

    if (key.isNull() || err) {
        // No such key most likely not OpenPGP
        return false;
    }
    if (!Kleo::canBeCertified(key)) {
        // key is expired or revoked
        return false;
    }
    if (key.hasSecret()) {
        qCDebug(KLEOPATRA_LOG) << q << __func__ << "Secret key is available -> skipping certification";
        return false;
    }

    for (const auto &uid : key.userIDs()) {
        if (uid.validity() >= GpgME::UserID::Marginal) {
            // Already marginal so don't bug the user
            return false;
        }
    }

    const QStringList suggestions = {
        i18n("A phone call to the person."),
        i18n("Using a business card."),
        i18n("Confirming it on a trusted website."),
    };

    auto sel = KMessageBox::questionTwoActions(parentWidgetOrView(),
                                               i18n("In order to mark the certificate as valid it needs to be certified.") + QStringLiteral("<br>")
                                                   + i18n("Certifying means that you check the Fingerprint.") + QStringLiteral("<br>")
                                                   + i18n("Some suggestions to do this are:")
                                                   + QStringLiteral("<li><ul>%1").arg(suggestions.join(QStringLiteral("</ul><ul>")))
                                                   + QStringLiteral("</ul></li>") + i18n("Do you wish to start this process now?"),
                                               i18nc("@title", "You have imported a new certificate (public key)"),
                                               KGuiItem(i18nc("@action:button", "Certify")),
                                               KStandardGuiItem::cancel(),
                                               QStringLiteral("CertifyQuestion"));
    if (sel == KMessageBox::ButtonCode::PrimaryAction) {
        QEventLoop loop;
        auto cmd = new Commands::CertifyCertificateCommand(key);
        cmd->setParentWidget(parentWidgetOrView());
        connect(cmd, &Command::finished, &loop, &QEventLoop::quit);
        QMetaObject::invokeMethod(cmd, &Commands::CertifyCertificateCommand::start, Qt::QueuedConnection);
        loop.exec();
    }
    return true;
}

namespace
{
/**
 * Returns the Import of an OpenPGP key, if a single certificate was imported and this was an OpenPGP key.
 * Otherwise, returns a null Import.
 */
auto getSingleOpenPGPImport(const std::vector<ImportResultData> &res)
{
    static const Import nullImport;
    if (!isImportFromSingleSource(res)) {
        return nullImport;
    }
    const auto numImported = std::accumulate(res.cbegin(), res.cend(), 0, [](auto s, const auto &r) {
        return s + r.result.numImported();
    });
    if (numImported > 1) {
        return nullImport;
    }
    if ((res.size() >= 1) && (res[0].protocol == GpgME::OpenPGP) && (res[0].result.numImported() == 1) && (res[0].result.imports().size() == 1)) {
        return res[0].result.imports()[0];
    } else if ((res.size() == 2) && (res[1].protocol == GpgME::OpenPGP) && (res[1].result.numImported() == 1) && (res[1].result.imports().size() == 1)) {
        return res[1].result.imports()[0];
    }
    return nullImport;
}

auto consolidatedAuditLogEntries(const std::vector<ImportResultData> &res)
{
    static const QString gpg = QStringLiteral("gpg");
    static const QString gpgsm = QStringLiteral("gpgsm");

    if (res.size() == 1) {
        return res.front().auditLog;
    }
    QStringList auditLogs;
    auto extractAndAnnotateAuditLog = [](const ImportResultData &r) {
        QString s;
        if (!r.id.isEmpty()) {
            const auto program = r.protocol == GpgME::OpenPGP ? gpg : gpgsm;
            const auto headerLine = i18nc("file name (imported with gpg/gpgsm)", "%1 (imported with %2)").arg(r.id, program);
            s += QStringLiteral("<div><b>%1</b></div>").arg(headerLine);
        }
        if (r.auditLog.error().code() == GPG_ERR_NO_DATA) {
            s += QStringLiteral("<em>") + i18nc("@info", "Audit log is empty.") + QStringLiteral("</em>");
        } else if (r.result.error().isCanceled()) {
            s += QStringLiteral("<em>") + i18nc("@info", "Import was canceled.") + QStringLiteral("</em>");
        } else {
            s += r.auditLog.text();
        }
        return s;
    };
    std::transform(res.cbegin(), res.cend(), std::back_inserter(auditLogs), extractAndAnnotateAuditLog);
    return AuditLogEntry{auditLogs.join(QLatin1StringView{"<hr>"}), Error{}};
}
}

void ImportCertificatesCommand::Private::showDetails(const std::vector<ImportResultData> &res, const std::vector<ImportedGroup> &groups)
{
    const auto singleOpenPGPImport = getSingleOpenPGPImport(res);

    setImportResultProxyModel(res);

    if (!singleOpenPGPImport.isNull()) {
        if (showPleaseCertify(singleOpenPGPImport)) {
            return;
        }
    }
    MessageBox::information(parentWidgetOrView(), make_message_report(res, groups), consolidatedAuditLogEntries(res), i18n("Certificate Import Result"));
}

static QString make_error_message(const Error &err, const QString &id)
{
    Q_ASSERT(err);
    Q_ASSERT(!err.isCanceled());
    if (id.isEmpty()) {
        return i18n(
            "<qt><p>An error occurred while trying to import the certificate:</p>"
            "<p><b>%1</b></p></qt>",
            Formatting::errorAsString(err));
    } else {
        return i18n(
            "<qt><p>An error occurred while trying to import the certificate %1:</p>"
            "<p><b>%2</b></p></qt>",
            id,
            Formatting::errorAsString(err));
    }
}

void ImportCertificatesCommand::Private::showError(const ImportResultData &result)
{
    MessageBox::error(parentWidgetOrView(), make_error_message(result.result.error(), result.id), result.auditLog);
}

void ImportCertificatesCommand::Private::setWaitForMoreJobs(bool wait)
{
    if (wait == waitForMoreJobs) {
        return;
    }
    waitForMoreJobs = wait;
    if (!waitForMoreJobs) {
        tryToFinish();
    }
}

void ImportCertificatesCommand::Private::onImportResult(const ImportResult &result, QGpgME::Job *finishedJob)
{
    if (!finishedJob) {
        finishedJob = qobject_cast<QGpgME::Job *>(q->sender());
    }
    Q_ASSERT(finishedJob);
    qCDebug(KLEOPATRA_LOG) << q << __func__ << finishedJob;

    auto it = std::find_if(std::begin(runningJobs), std::end(runningJobs), [finishedJob](const auto &job) {
        return job.job == finishedJob;
    });
    Q_ASSERT(it != std::end(runningJobs));
    if (it == std::end(runningJobs)) {
        qCWarning(KLEOPATRA_LOG) << __func__ << "Error: Finished job not found";
        return;
    }

    Kleo::for_each(it->connections, &disconnectConnection);
    it->connections.clear();

    increaseProgressValue();

    const auto job = *it;
    addImportResult({job.id, job.protocol, job.type, result, AuditLogEntry::fromJob(finishedJob)}, job);
}

void ImportCertificatesCommand::Private::addImportResult(const ImportResultData &result, const ImportJobData &job)
{
    qCDebug(KLEOPATRA_LOG) << q << __func__ << result.id << "Result:" << Formatting::errorAsString(result.result.error());
    results.push_back(result);

    if (importFailed(result)) {
        showError(result);
    }

    if (job.job) {
        const auto count = std::erase(runningJobs, job);
        Q_ASSERT(count == 1);
    }

    tryToFinish();
}

static void handleOwnerTrust(const std::vector<ImportResultData> &results, QWidget *dialog)
{
    std::unordered_set<std::string> askedAboutFingerprints;
    for (const auto &r : results) {
        if (r.protocol != GpgME::Protocol::OpenPGP) {
            qCDebug(KLEOPATRA_LOG) << __func__ << "Skipping non-OpenPGP import";
            continue;
        }
        const auto imports = r.result.imports();
        for (const auto &import : imports) {
            if (!(import.status() & (Import::Status::NewKey | Import::Status::ContainedSecretKey))) {
                qCDebug(KLEOPATRA_LOG) << __func__ << "Skipping already known imported public key";
                continue;
            }
            const char *fpr = import.fingerprint();
            if (!fpr) {
                qCDebug(KLEOPATRA_LOG) << __func__ << "Skipping import without fingerprint";
                continue;
            }
            if (Kleo::contains(askedAboutFingerprints, fpr)) {
                // imports of secret keys can result in multiple Imports for the same key
                qCDebug(KLEOPATRA_LOG) << __func__ << "Skipping import for already handled fingerprint";
                continue;
            }

            GpgME::Error err;
            auto ctx = wrap_unique(Context::createForProtocol(GpgME::Protocol::OpenPGP));
            if (!ctx) {
                qCWarning(KLEOPATRA_LOG) << "Failed to get context";
                continue;
            }

            ctx->addKeyListMode(KeyListMode::WithSecret);
            const Key toTrustOwner = ctx->key(fpr, err, false);

            if (toTrustOwner.isNull() || !toTrustOwner.hasSecret()) {
                continue;
            }
            if (toTrustOwner.ownerTrust() == Key::OwnerTrust::Ultimate) {
                qCDebug(KLEOPATRA_LOG) << __func__ << "Skipping key with ultimate ownertrust";
                continue;
            }

            const auto toTrustOwnerUserIDs{toTrustOwner.userIDs()};
            // ki18n(" ") as initializer because initializing with empty string leads to
            // (I18N_EMPTY_MESSAGE)
            const KLocalizedString uids = std::accumulate(toTrustOwnerUserIDs.cbegin(),
                                                          toTrustOwnerUserIDs.cend(),
                                                          KLocalizedString{ki18n(" ")},
                                                          [](KLocalizedString temp, const auto &uid) {
                                                              return kxi18nc("@info", "%1<item>%2</item>").subs(temp).subs(Formatting::prettyNameAndEMail(uid));
                                                          });

            const QString str = xi18nc("@info",
                                       "<para>You have imported a certificate with fingerprint</para>"
                                       "<para><numid>%1</numid></para>"
                                       "<para>"
                                       "and user IDs"
                                       "<list>%2</list>"
                                       "</para>"
                                       "<para>Is this your own certificate?</para>",
                                       Formatting::prettyID(fpr),
                                       uids);

            int k = KMessageBox::questionTwoActionsCancel(dialog,
                                                          str,
                                                          i18nc("@title:window", "Mark Own Certificate"),
                                                          KGuiItem{i18nc("@action:button", "Yes, It's Mine")},
                                                          KGuiItem{i18nc("@action:button", "No, It's Not Mine")});
            askedAboutFingerprints.insert(fpr);

            if (k == KMessageBox::ButtonCode::PrimaryAction) {
                // To use the ChangeOwnerTrustJob over
                // the CryptoBackendFactory
                const QGpgME::Protocol *const backend = QGpgME::openpgp();

                if (!backend) {
                    qCWarning(KLEOPATRA_LOG) << "Failed to get CryptoBackend";
                    return;
                }

                ChangeOwnerTrustJob *const j = backend->changeOwnerTrustJob();
                j->start(toTrustOwner, Key::Ultimate);
            } else if (k == KMessageBox::ButtonCode::Cancel) {
                // do not bother the user with further "Is this yours?" questions
                return;
            }
        }
    }
}

static void validateImportedCertificate(const GpgME::Import &import)
{
    if (const auto fpr = import.fingerprint()) {
        auto key = KeyCache::instance()->findByFingerprint(fpr);
        if (!key.isNull()) {
            // this triggers a keylisting with validation for this certificate
            key.update();
        } else {
            qCWarning(KLEOPATRA_LOG) << __func__ << "Certificate with fingerprint" << fpr << "not found";
        }
    }
}

static void handleExternalCMSImports(const std::vector<ImportResultData> &results)
{
    // For external CMS Imports we have to manually do a keylist
    // with validation to get the intermediate and root ca imported
    // automatically if trusted-certs and extra-certs are used.
    for (const auto &r : results) {
        if (r.protocol == GpgME::CMS && r.type == ImportType::External && !importFailed(r) && !importWasCanceled(r)) {
            const auto imports = r.result.imports();
            std::for_each(std::begin(imports), std::end(imports), &validateImportedCertificate);
        }
    }
}

void ImportCertificatesCommand::Private::processResults()
{
    importGroups();

    if (Settings{}.retrieveSignerKeysAfterImport() && !importingSignerKeys) {
        importingSignerKeys = true;
        const auto missingSignerKeys = getMissingSignerKeyIds(results);
        if (!missingSignerKeys.empty()) {
            importSignerKeys(missingSignerKeys);
            return;
        }
    }

    handleExternalCMSImports(results);

    // ensure that the progress dialog is closed before we show any other dialogs
    setProgressToMaximum();

    handleOwnerTrust(results, parentWidgetOrView());

    auto hasError = std::ranges::any_of(results, [](const auto &result) {
        return importFailed(result);
    });
    auto allAreIrrelevant = std::ranges::all_of(results, [](const auto &result) {
        return result.result.numConsidered() == 0 || (importFailed(result) && result.result.numConsidered() == 1);
    });
    if (!(hasError && allAreIrrelevant)) {
        showDetails(results, importedGroups);
    }

    auto tv = dynamic_cast<QTreeView *>(view());
    if (!tv) {
        qCDebug(KLEOPATRA_LOG) << "Failed to find treeview";
    } else {
        tv->expandAll();
    }
    finished();
}

void ImportCertificatesCommand::Private::tryToFinish()
{
    qCDebug(KLEOPATRA_LOG) << q << __func__;
    if (waitForMoreJobs) {
        qCDebug(KLEOPATRA_LOG) << q << __func__ << "Waiting for more jobs -> keep going";
        return;
    }
    if (!runningJobs.empty()) {
        qCDebug(KLEOPATRA_LOG) << q << __func__ << "There are unfinished jobs -> keep going";
        return;
    }
    if (!pendingJobs.empty()) {
        qCDebug(KLEOPATRA_LOG) << q << __func__ << "There are pending jobs -> start the next one";
        auto job = pendingJobs.front();
        pendingJobs.pop();
        job.job->startNow();
        runningJobs.push_back(job);
        return;
    }

    if (keyListConnection) {
        qCWarning(KLEOPATRA_LOG) << q << __func__ << "There is already a valid keyListConnection!";
    } else {
        auto keyCache = KeyCache::mutableInstance();
        keyListConnection = connect(keyCache.get(), &KeyCache::keyListingDone, q, [this]() {
            keyCacheUpdated();
        });
        keyCache->startKeyListing();
    }
}

void ImportCertificatesCommand::Private::keyCacheUpdated()
{
    qCDebug(KLEOPATRA_LOG) << q << __func__;
    if (!disconnect(keyListConnection)) {
        qCWarning(KLEOPATRA_LOG) << q << __func__ << "Failed to disconnect keyListConnection";
    }

    keyCacheAutoRefreshSuspension.reset();

    const auto allIds = std::accumulate(std::cbegin(results), std::cend(results), std::set<QString>{}, [](auto allIds, const auto &r) {
        allIds.insert(r.id);
        return allIds;
    });
    const auto canceledIds = std::accumulate(std::cbegin(results), std::cend(results), std::set<QString>{}, [](auto canceledIds, const auto &r) {
        if (importWasCanceled(r)) {
            canceledIds.insert(r.id);
        }
        return canceledIds;
    });
    const auto totalConsidered = std::accumulate(std::cbegin(results), std::cend(results), 0, [](auto totalConsidered, const auto &r) {
        return totalConsidered + r.result.numConsidered();
    });
    if (totalConsidered == 0 && canceledIds.size() == allIds.size()) {
        // nothing was considered for import and at least one import per id was
        // canceled => treat the command as canceled
        canceled();
        return;
    }

    processResults();
}

static ImportedGroup storeGroup(const KeyGroup &group, const QString &id, QWidget *parent)
{
    if (std::ranges::any_of(group.keys(), [](const auto &key) {
            return !Kleo::keyHasEncrypt(key);
        })) {
        KMessageBox::information(parent,
                                 xi18nc("@info",
                                        "<para>The imported group</para><para><emphasis>%1</emphasis></para><para>contains certificates that cannot be used for encryption. "
                                        "This may lead to unexpected results.</para>",
                                        group.name()));
    }
    const auto status = KeyCache::instance()->group(group.id()).isNull() ? ImportedGroup::Status::New : ImportedGroup::Status::Updated;
    if (status == ImportedGroup::Status::New) {
        KeyCache::mutableInstance()->insert(group);
    } else {
        KeyCache::mutableInstance()->update(group);
    }
    return {id, group, status};
}

void ImportCertificatesCommand::Private::importGroups()
{
    for (const auto &path : filesToImportGroupsFrom) {
        const bool certificateImportSucceeded = std::any_of(std::cbegin(results), std::cend(results), [path](const auto &r) {
            return r.id == path && !importFailed(r) && !importWasCanceled(r);
        });
        if (certificateImportSucceeded) {
            qCDebug(KLEOPATRA_LOG) << __func__ << "Importing groups from file" << path;
            const auto groups = readKeyGroups(path);
            std::transform(std::begin(groups), std::end(groups), std::back_inserter(importedGroups), [path, this](const auto &group) {
                return storeGroup(group, path, parentWidgetOrView());
            });
        }
        increaseProgressValue();
    }
    filesToImportGroupsFrom.clear();
}

static auto accumulateNewKeys(std::vector<std::string> &fingerprints, const std::vector<GpgME::Import> &imports)
{
    return std::accumulate(std::begin(imports), std::end(imports), fingerprints, [](auto fingerprints, const auto &import) {
        if (import.status() == Import::NewKey) {
            fingerprints.push_back(import.fingerprint());
        }
        return fingerprints;
    });
}

static auto accumulateNewOpenPGPKeys(const std::vector<ImportResultData> &results)
{
    return std::accumulate(std::begin(results), std::end(results), std::vector<std::string>{}, [](auto fingerprints, const auto &r) {
        if (r.protocol == GpgME::OpenPGP) {
            fingerprints = accumulateNewKeys(fingerprints, r.result.imports());
        }
        return fingerprints;
    });
}

std::set<QString> ImportCertificatesCommand::Private::getMissingSignerKeyIds(const std::vector<ImportResultData> &results)
{
    auto newOpenPGPKeys = KeyCache::instance()->findByFingerprint(accumulateNewOpenPGPKeys(results));
    // update all new OpenPGP keys to get information about certifications
    std::for_each(std::begin(newOpenPGPKeys), std::end(newOpenPGPKeys), std::mem_fn(&Key::update));
    auto missingSignerKeyIds = Kleo::getMissingSignerKeyIds(newOpenPGPKeys);
    return missingSignerKeyIds;
}

void ImportCertificatesCommand::Private::importSignerKeys(const std::set<QString> &keyIds)
{
    Q_ASSERT(!keyIds.empty());

    setProgressLabelText(i18np("Fetching 1 signer key... (this can take a while)", "Fetching %1 signer keys... (this can take a while)", keyIds.size()));

    setWaitForMoreJobs(true);
    // start one import per key id to allow canceling the key retrieval without
    // losing already retrieved keys
    for (const auto &keyId : keyIds) {
        startImport(GpgME::OpenPGP, {keyId}, QStringLiteral("Retrieve Signer Keys"));
    }
    setWaitForMoreJobs(false);
}

static std::unique_ptr<ImportJob> get_import_job(GpgME::Protocol protocol)
{
    Q_ASSERT(protocol != UnknownProtocol);
    if (const auto backend = (protocol == GpgME::OpenPGP ? QGpgME::openpgp() : QGpgME::smime())) {
        return std::unique_ptr<ImportJob>(backend->importJob());
    } else {
        return std::unique_ptr<ImportJob>();
    }
}

void ImportCertificatesCommand::Private::startImport(GpgME::Protocol protocol,
                                                     const QByteArray &data,
                                                     const QString &id,
                                                     [[maybe_unused]] const ImportOptions &options)
{
    Q_ASSERT(protocol != UnknownProtocol);

    if (std::find(nonWorkingProtocols.cbegin(), nonWorkingProtocols.cend(), protocol) != nonWorkingProtocols.cend()) {
        return;
    }

    std::unique_ptr<ImportJob> job = get_import_job(protocol);
    if (!job.get()) {
        nonWorkingProtocols.push_back(protocol);
        error(i18n("The type of this certificate (%1) is not supported by this Kleopatra installation.", Formatting::displayName(protocol)),
              i18n("Certificate Import Failed"));
        addImportResult({id, protocol, ImportType::Local, ImportResult{}, AuditLogEntry{}});
        return;
    }

    keyCacheAutoRefreshSuspension = KeyCache::mutableInstance()->suspendAutoRefresh();

    std::vector<QMetaObject::Connection> connections = {
        connect(job.get(),
                &AbstractImportJob::result,
                q,
                [this](const GpgME::ImportResult &result) {
                    onImportResult(result);
                }),
        connect(job.get(), &QGpgME::Job::jobProgress, q, &Command::progress),
    };

    job->setImportFilter(options.importFilter);
#if QGPGME_IMPORT_JOB_SUPPORTS_IMPORT_OPTIONS
    job->setImportOptions(options.importOptions);
#endif
    job->setKeyOrigin(options.keyOrigin, options.keyOriginUrl);
    const GpgME::Error err = job->startLater(data);
    if (err.code()) {
        addImportResult({id, protocol, ImportType::Local, ImportResult{err}, AuditLogEntry{}});
    } else {
        increaseProgressMaximum();
        pendingJobs.push({id, protocol, ImportType::Local, job.release(), connections});
    }
}

static std::unique_ptr<ImportFromKeyserverJob> get_import_from_keyserver_job(GpgME::Protocol protocol)
{
    Q_ASSERT(protocol != UnknownProtocol);
    if (const auto backend = (protocol == GpgME::OpenPGP ? QGpgME::openpgp() : QGpgME::smime())) {
        return std::unique_ptr<ImportFromKeyserverJob>(backend->importFromKeyserverJob());
    } else {
        return std::unique_ptr<ImportFromKeyserverJob>();
    }
}

void ImportCertificatesCommand::Private::startImport(GpgME::Protocol protocol, const std::vector<Key> &keys, const QString &id)
{
    Q_ASSERT(protocol != UnknownProtocol);

    if (std::find(nonWorkingProtocols.cbegin(), nonWorkingProtocols.cend(), protocol) != nonWorkingProtocols.cend()) {
        return;
    }

    std::unique_ptr<ImportFromKeyserverJob> job = get_import_from_keyserver_job(protocol);
    if (!job.get()) {
        nonWorkingProtocols.push_back(protocol);
        error(i18n("The type of this certificate (%1) is not supported by this Kleopatra installation.", Formatting::displayName(protocol)),
              i18n("Certificate Import Failed"));
        addImportResult({id, protocol, ImportType::External, ImportResult{}, AuditLogEntry{}});
        return;
    }

    keyCacheAutoRefreshSuspension = KeyCache::mutableInstance()->suspendAutoRefresh();

    std::vector<QMetaObject::Connection> connections = {
        connect(job.get(),
                &AbstractImportJob::result,
                q,
                [this](const GpgME::ImportResult &result) {
                    onImportResult(result);
                }),
        connect(job.get(), &QGpgME::Job::jobProgress, q, &Command::progress),
    };

    const GpgME::Error err = job->start(keys);
    if (err.code()) {
        addImportResult({id, protocol, ImportType::External, ImportResult{err}, AuditLogEntry{}});
    } else {
        increaseProgressMaximum();
        runningJobs.push_back({id, protocol, ImportType::External, job.release(), connections});
    }
}

static auto get_receive_keys_job(GpgME::Protocol protocol)
{
    Q_ASSERT(protocol != UnknownProtocol);

    std::unique_ptr<ReceiveKeysJob> job{};
    if (const auto backend = (protocol == GpgME::OpenPGP ? QGpgME::openpgp() : QGpgME::smime())) {
        job.reset(backend->receiveKeysJob());
    }
    return job;
}

void ImportCertificatesCommand::Private::startImport(GpgME::Protocol protocol, [[maybe_unused]] const QStringList &keyIds, const QString &id)
{
    Q_ASSERT(protocol != UnknownProtocol);

    auto job = get_receive_keys_job(protocol);
    if (!job.get()) {
        qCWarning(KLEOPATRA_LOG) << "Failed to get ReceiveKeysJob for protocol" << Formatting::displayName(protocol);
        addImportResult({id, protocol, ImportType::External, ImportResult{}, AuditLogEntry{}});
        return;
    }

    keyCacheAutoRefreshSuspension = KeyCache::mutableInstance()->suspendAutoRefresh();

    std::vector<QMetaObject::Connection> connections = {
        connect(job.get(),
                &AbstractImportJob::result,
                q,
                [this](const GpgME::ImportResult &result) {
                    onImportResult(result);
                }),
        connect(job.get(), &QGpgME::Job::jobProgress, q, &Command::progress),
    };

    const GpgME::Error err = job->start(keyIds);
    if (err.code()) {
        addImportResult({id, protocol, ImportType::External, ImportResult{err}, AuditLogEntry{}});
    } else {
        increaseProgressMaximum();
        runningJobs.push_back({id, protocol, ImportType::External, job.release(), connections});
    }
}

void ImportCertificatesCommand::Private::importGroupsFromFile(const QString &filename)
{
    increaseProgressMaximum();
    filesToImportGroupsFrom.push_back(filename);
}

void ImportCertificatesCommand::Private::setUpProgressDialog()
{
    if (progressDialog) {
        return;
    }
    progressDialog = new QProgressDialog{parentWidgetOrView()};
    // use a non-modal progress dialog to avoid reentrancy problems (and crashes) if multiple jobs finish in the same event loop cycle
    // (cf. the warning for QProgressDialog::setValue() in the API documentation)
    progressDialog->setModal(false);
    progressDialog->setWindowTitle(progressWindowTitle);
    progressDialog->setLabelText(progressLabelText);
    progressDialog->setMinimumDuration(1000);
    progressDialog->setMaximum(1);
    progressDialog->setValue(0);
    connect(progressDialog, &QProgressDialog::canceled, q, &Command::cancel);
    connect(q, &Command::finished, progressDialog, [this]() {
        progressDialog->accept();
    });
}

void ImportCertificatesCommand::Private::setProgressWindowTitle(const QString &title)
{
    if (progressDialog) {
        progressDialog->setWindowTitle(title);
    } else {
        progressWindowTitle = title;
    }
}

void ImportCertificatesCommand::Private::setProgressLabelText(const QString &text)
{
    if (progressDialog) {
        progressDialog->setLabelText(text);
    } else {
        progressLabelText = text;
    }
}

void ImportCertificatesCommand::Private::increaseProgressMaximum()
{
    setUpProgressDialog();
    progressDialog->setMaximum(progressDialog->maximum() + 1);
    qCDebug(KLEOPATRA_LOG) << __func__ << "progress:" << progressDialog->value() << "/" << progressDialog->maximum();
}

void ImportCertificatesCommand::Private::increaseProgressValue()
{
    progressDialog->setValue(progressDialog->value() + 1);
    qCDebug(KLEOPATRA_LOG) << __func__ << "progress:" << progressDialog->value() << "/" << progressDialog->maximum();
}

void ImportCertificatesCommand::Private::setProgressToMaximum()
{
    qCDebug(KLEOPATRA_LOG) << __func__;
    progressDialog->setValue(progressDialog->maximum());
}

void ImportCertificatesCommand::doCancel()
{
    const auto jobsToCancel = d->runningJobs;
    std::for_each(std::begin(jobsToCancel), std::end(jobsToCancel), [this](const auto &job) {
        if (!job.connections.empty()) {
            // ignore jobs without connections; they are already completed
            qCDebug(KLEOPATRA_LOG) << "Canceling job" << job.job;
            job.job->slotCancel();
            d->onImportResult(ImportResult{Error::fromCode(GPG_ERR_CANCELED)}, job.job);
        }
    });
}

#undef d
#undef q

#include "importcertificatescommand.moc"
#include "moc_importcertificatescommand.cpp"
