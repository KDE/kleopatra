/* -*- mode: c++; c-basic-offset:4 -*-
    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2007 Klarälvdalens Datakonsult AB

    SPDX-FileCopyrightText: 2017 Bundesamt für Sicherheit in der Informationstechnik
    SPDX-FileContributor: Intevation GmbH

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include <config-kleopatra.h>

#include "signencryptfilescontroller.h"

#include "signencrypttask.h"

#include "crypto/gui/signencryptfilesdialog.h"
#include "crypto/taskcollection.h"

#include "fileoperationspreferences.h"

#include "utils/archivedefinition.h"
#include "utils/input.h"
#include "utils/kleo_assert.h"
#include "utils/output.h"
#include "utils/path-helper.h"

#include <Libkleo/Classify>
#include <Libkleo/KleoException>

#include "kleopatra_debug.h"
#include <KLocalizedString>

#include <QGpgME/SignEncryptArchiveJob>

#include <QDir>
#include <QFileInfo>
#include <QPointer>
#include <QTimer>

using namespace Kleo;
using namespace Kleo::Crypto;
using namespace GpgME;

class SignEncryptFilesController::Private
{
    friend class ::Kleo::Crypto::SignEncryptFilesController;
    SignEncryptFilesController *const q;

public:
    explicit Private(SignEncryptFilesController *qq);
    ~Private();

private:
    void slotWizardOperationPrepared();
    void slotWizardCanceled();

private:
    void ensureWizardCreated();
    void ensureWizardVisible();
    void updateWizardMode();
    void cancelAllTasks();
    void reportError(int err, const QString &details)
    {
        q->setLastError(err, details);
        q->emitDoneOrError();
    }

    void schedule();
    std::shared_ptr<SignEncryptTask> takeRunnable(GpgME::Protocol proto);

    static void assertValidOperation(unsigned int);
    static QString titleForOperation(unsigned int op);

private:
    std::vector<std::shared_ptr<SignEncryptTask>> runnable, completed;
    std::shared_ptr<SignEncryptTask> cms, openpgp;
    QPointer<SignEncryptFilesDialog> wizard;
    QStringList files;
    unsigned int operation;
    Protocol protocol;
};

SignEncryptFilesController::Private::Private(SignEncryptFilesController *qq)
    : q(qq)
    , runnable()
    , cms()
    , openpgp()
    , wizard()
    , files()
    , operation(SignAllowed | EncryptAllowed | ArchiveAllowed)
    , protocol(UnknownProtocol)
{
}

SignEncryptFilesController::Private::~Private()
{
    qCDebug(KLEOPATRA_LOG) << q << __func__;
}

QString SignEncryptFilesController::Private::titleForOperation(unsigned int op)
{
    const bool signDisallowed = (op & SignMask) == SignDisallowed;
    const bool encryptDisallowed = (op & EncryptMask) == EncryptDisallowed;
    const bool archiveSelected = (op & ArchiveMask) == ArchiveForced;

    kleo_assert(!signDisallowed || !encryptDisallowed);

    if (!signDisallowed && encryptDisallowed) {
        if (archiveSelected) {
            return i18n("Archive and Sign Files");
        } else {
            return i18n("Sign Files");
        }
    }

    if (signDisallowed && !encryptDisallowed) {
        if (archiveSelected) {
            return i18n("Archive and Encrypt Files");
        } else {
            return i18n("Encrypt Files");
        }
    }

    if (archiveSelected) {
        return i18n("Archive and Sign/Encrypt Files");
    } else {
        return i18n("Sign/Encrypt Files");
    }
}

SignEncryptFilesController::SignEncryptFilesController(QObject *p)
    : Controller(p)
    , d(new Private(this))
{
}

SignEncryptFilesController::SignEncryptFilesController(const std::shared_ptr<const ExecutionContext> &ctx, QObject *p)
    : Controller(ctx, p)
    , d(new Private(this))
{
}

SignEncryptFilesController::~SignEncryptFilesController()
{
    qCDebug(KLEOPATRA_LOG) << this << __func__;
    if (d->wizard && !d->wizard->isVisible()) {
        delete d->wizard;
    }
    // d->wizard->close(); ### ?
}

void SignEncryptFilesController::setProtocol(Protocol proto)
{
    kleo_assert(d->protocol == UnknownProtocol || d->protocol == proto);
    d->protocol = proto;
    d->ensureWizardCreated();
}

Protocol SignEncryptFilesController::protocol() const
{
    return d->protocol;
}

// static
void SignEncryptFilesController::Private::assertValidOperation(unsigned int op)
{
    kleo_assert((op & SignMask) == SignDisallowed || //
                (op & SignMask) == SignAllowed || //
                (op & SignMask) == SignSelected);
    kleo_assert((op & EncryptMask) == EncryptDisallowed || //
                (op & EncryptMask) == EncryptAllowed || //
                (op & EncryptMask) == EncryptSelected);
    kleo_assert((op & ArchiveMask) == ArchiveDisallowed || //
                (op & ArchiveMask) == ArchiveAllowed || //
                (op & ArchiveMask) == ArchiveForced);
    kleo_assert((op & ~(SignMask | EncryptMask | ArchiveMask)) == 0);
}

void SignEncryptFilesController::setOperationMode(unsigned int mode)
{
    Private::assertValidOperation(mode);
    d->operation = mode;
    d->updateWizardMode();
}

void SignEncryptFilesController::Private::updateWizardMode()
{
    if (!wizard) {
        return;
    }
    wizard->setWindowTitle(titleForOperation(operation));
    const unsigned int signOp = (operation & SignMask);
    const unsigned int encrOp = (operation & EncryptMask);
    const unsigned int archOp = (operation & ArchiveMask);

    if (signOp == SignDisallowed) {
        wizard->setSigningUserMutable(false);
        wizard->setSigningPreset(false);
    } else {
        wizard->setSigningUserMutable(true);
        wizard->setSigningPreset(signOp == SignSelected);
    }

    if (encrOp == EncryptDisallowed) {
        wizard->setEncryptionPreset(false);
        wizard->setEncryptionUserMutable(false);
    } else {
        wizard->setEncryptionUserMutable(true);
        wizard->setEncryptionPreset(encrOp == EncryptSelected);
    }

    wizard->setArchiveForced(archOp == ArchiveForced);
    wizard->setArchiveMutable(archOp == ArchiveAllowed);
}

unsigned int SignEncryptFilesController::operationMode() const
{
    return d->operation;
}

static QString extension(bool pgp, bool sign, bool encrypt, bool ascii, bool detached)
{
    unsigned int cls = pgp ? Class::OpenPGP : Class::CMS;
    if (encrypt) {
        cls |= Class::CipherText;
    } else if (sign) {
        cls |= detached ? Class::DetachedSignature : Class::OpaqueSignature;
    }
    cls |= ascii ? Class::Ascii : Class::Binary;
    const bool usePGPFileExt = FileOperationsPreferences().usePGPFileExt();
    const auto ext = outputFileExtension(cls, usePGPFileExt);
    if (!ext.isEmpty()) {
        return ext;
    } else {
        return QStringLiteral("out");
    }
}

static std::shared_ptr<ArchiveDefinition> getDefaultAd()
{
    const std::vector<std::shared_ptr<ArchiveDefinition>> ads = ArchiveDefinition::getArchiveDefinitions();
    Q_ASSERT(!ads.empty());
    std::shared_ptr<ArchiveDefinition> ad = ads.front();
    const FileOperationsPreferences prefs;
    const QString archiveCmd = prefs.archiveCommand();
    auto it = std::find_if(ads.cbegin(), ads.cend(), [&archiveCmd](const std::shared_ptr<ArchiveDefinition> &toCheck) {
        return toCheck->id() == archiveCmd;
    });
    if (it != ads.cend()) {
        ad = *it;
    }
    return ad;
}

static QMap<int, QString> buildOutputNames(const QStringList &files, const bool archive)
{
    QMap<int, QString> nameMap;

    // Build the default names for the wizard.
    QString baseNameCms;
    QString baseNamePgp;
    const QFileInfo firstFile(files.first());
    if (archive) {
        QString baseName = files.size() > 1 ? i18nc("base name of an archive file, e.g. archive.zip or archive.tar.gz", "archive") : firstFile.baseName();
        baseName = QDir(heuristicBaseDirectory(files)).absoluteFilePath(baseName);

        const auto ad = getDefaultAd();
        baseNamePgp = baseName + QLatin1Char('.') + ad->extensions(GpgME::OpenPGP).first() + QLatin1Char('.');
        baseNameCms = baseName + QLatin1Char('.') + ad->extensions(GpgME::CMS).first() + QLatin1Char('.');
    } else {
        baseNameCms = baseNamePgp = files.first() + QLatin1Char('.');
    }
    const FileOperationsPreferences prefs;
    const bool ascii = prefs.addASCIIArmor();

    nameMap.insert(SignEncryptFilesDialog::SignatureCMS, baseNameCms + extension(false, true, false, ascii, true));
    nameMap.insert(SignEncryptFilesDialog::EncryptedCMS, baseNameCms + extension(false, false, true, ascii, false));
    nameMap.insert(SignEncryptFilesDialog::CombinedPGP, baseNamePgp + extension(true, true, true, ascii, false));
    nameMap.insert(SignEncryptFilesDialog::EncryptedPGP, baseNamePgp + extension(true, false, true, ascii, false));
    nameMap.insert(SignEncryptFilesDialog::SignaturePGP, baseNamePgp + extension(true, true, false, ascii, true));
    nameMap.insert(SignEncryptFilesDialog::Directory, heuristicBaseDirectory(files));
    return nameMap;
}

static QMap<int, QString> buildOutputNamesForDir(const QString &file, const QMap<int, QString> &orig)
{
    QMap<int, QString> ret;

    const QString dir = orig.value(SignEncryptFilesDialog::Directory);
    if (dir.isEmpty()) {
        return orig;
    }

    // Build the default names for the wizard.
    const QFileInfo fi(file);
    const QString baseName = dir + QLatin1Char('/') + fi.fileName() + QLatin1Char('.');

    const FileOperationsPreferences prefs;
    const bool ascii = prefs.addASCIIArmor();

    ret.insert(SignEncryptFilesDialog::SignatureCMS, baseName + extension(false, true, false, ascii, true));
    ret.insert(SignEncryptFilesDialog::EncryptedCMS, baseName + extension(false, false, true, ascii, false));
    ret.insert(SignEncryptFilesDialog::CombinedPGP, baseName + extension(true, true, true, ascii, false));
    ret.insert(SignEncryptFilesDialog::EncryptedPGP, baseName + extension(true, false, true, ascii, false));
    ret.insert(SignEncryptFilesDialog::SignaturePGP, baseName + extension(true, true, false, ascii, true));
    return ret;
}

// strips all trailing slashes from the filename, but keeps filename "/"
static QString stripTrailingSlashes(const QString &fileName)
{
    if (fileName.size() < 2 || !fileName.endsWith(QLatin1Char('/'))) {
        return fileName;
    }
    auto tmp = QStringView{fileName}.chopped(1);
    while (tmp.size() > 1 && tmp.endsWith(QLatin1Char('/'))) {
        tmp.chop(1);
    }
    return tmp.toString();
}

static QStringList stripTrailingSlashesForAll(const QStringList &fileNames)
{
    QStringList result;
    result.reserve(fileNames.size());
    std::transform(fileNames.begin(), fileNames.end(), std::back_inserter(result), &stripTrailingSlashes);
    return result;
}

void SignEncryptFilesController::setFiles(const QStringList &files)
{
    kleo_assert(!files.empty());
    d->files = stripTrailingSlashesForAll(files);
    bool archive = false;

    if (d->files.size() > 1) {
        setOperationMode((operationMode() & ~ArchiveMask) | ArchiveAllowed);
        archive = true;
    }
    for (const auto &file : std::as_const(d->files)) {
        if (QFileInfo(file).isDir()) {
            setOperationMode((operationMode() & ~ArchiveMask) | ArchiveForced);
            archive = true;
            break;
        }
    }
    d->ensureWizardCreated();
    d->wizard->setSingleFile(!archive);
    d->wizard->setOutputNames(buildOutputNames(d->files, archive));
}

void SignEncryptFilesController::Private::slotWizardCanceled()
{
    qCDebug(KLEOPATRA_LOG) << q << __func__;
    q->cancel();
    reportError(gpg_error(GPG_ERR_CANCELED), i18n("User cancel"));
}

void SignEncryptFilesController::start()
{
    d->ensureWizardVisible();
}

static std::shared_ptr<SignEncryptTask> createSignEncryptTaskForFileInfo(const QFileInfo &fi,
                                                                         bool ascii,
                                                                         const std::vector<Key> &recipients,
                                                                         const std::vector<Key> &signers,
                                                                         const QString &outputName,
                                                                         bool symmetric)
{
    const std::shared_ptr<SignEncryptTask> task(new SignEncryptTask);
    Q_ASSERT(!signers.empty() || !recipients.empty() || symmetric);
    task->setAsciiArmor(ascii);
    if (!signers.empty()) {
        task->setSign(true);
        task->setSigners(signers);
        task->setDetachedSignature(true);
    } else {
        task->setSign(false);
    }
    if (!recipients.empty()) {
        task->setEncrypt(true);
        task->setRecipients(recipients);
        task->setDetachedSignature(false);
    } else {
        task->setEncrypt(false);
    }
    task->setEncryptSymmetric(symmetric);
    const QString input = fi.absoluteFilePath();
    task->setInputFileName(input);
#if QGPGME_FILE_JOBS_SUPPORT_DIRECT_FILE_IO
    if (task->protocol() != GpgME::OpenPGP) {
        task->setInput(Input::createFromFile(input));
    }
#else
    task->setInput(Input::createFromFile(input));
#endif

    task->setOutputFileName(outputName);

    return task;
}

static bool archiveJobsCanBeUsed([[maybe_unused]] GpgME::Protocol protocol)
{
    return (protocol == GpgME::OpenPGP) && QGpgME::SignEncryptArchiveJob::isSupported();
}

static std::shared_ptr<SignEncryptTask> createArchiveSignEncryptTaskForFiles(const QStringList &files,
                                                                             const std::shared_ptr<ArchiveDefinition> &ad,
                                                                             bool pgp,
                                                                             bool ascii,
                                                                             const std::vector<Key> &recipients,
                                                                             const std::vector<Key> &signers,
                                                                             const QString &outputName,
                                                                             bool symmetric)
{
    const std::shared_ptr<SignEncryptTask> task(new SignEncryptTask);
    task->setCreateArchive(true);
    task->setEncryptSymmetric(symmetric);
    Q_ASSERT(!signers.empty() || !recipients.empty() || symmetric);
    task->setAsciiArmor(ascii);
    if (!signers.empty()) {
        task->setSign(true);
        task->setSigners(signers);
        task->setDetachedSignature(false);
    } else {
        task->setSign(false);
    }
    if (!recipients.empty()) {
        task->setEncrypt(true);
        task->setRecipients(recipients);
    } else {
        task->setEncrypt(false);
    }

    const Protocol proto = pgp ? OpenPGP : CMS;

    task->setInputFileNames(files);
    if (!archiveJobsCanBeUsed(proto)) {
        // use legacy archive creation
        kleo_assert(ad);
        task->setInput(ad->createInputFromPackCommand(proto, files));
    }

    task->setOutputFileName(outputName);

    return task;
}

static std::vector<std::shared_ptr<SignEncryptTask>> createSignEncryptTasksForFileInfo(const QFileInfo &fi,
                                                                                       bool ascii,
                                                                                       const std::vector<Key> &pgpRecipients,
                                                                                       const std::vector<Key> &pgpSigners,
                                                                                       const std::vector<Key> &cmsRecipients,
                                                                                       const std::vector<Key> &cmsSigners,
                                                                                       const QMap<int, QString> &outputNames,
                                                                                       bool symmetric)
{
    std::vector<std::shared_ptr<SignEncryptTask>> result;

    const bool pgp = !pgpSigners.empty() || !pgpRecipients.empty();

    const bool cms = !cmsSigners.empty() || !cmsRecipients.empty();

    result.reserve(pgp + cms);

    if (pgp || symmetric) {
        // Symmetric encryption is only supported for PGP
        int outKind = 0;
        if ((!pgpRecipients.empty() || symmetric) && !pgpSigners.empty()) {
            outKind = SignEncryptFilesDialog::CombinedPGP;
        } else if (!pgpRecipients.empty() || symmetric) {
            outKind = SignEncryptFilesDialog::EncryptedPGP;
        } else {
            outKind = SignEncryptFilesDialog::SignaturePGP;
        }
        result.push_back(createSignEncryptTaskForFileInfo(fi, ascii, pgpRecipients, pgpSigners, outputNames[outKind], symmetric));
    }
    if (cms) {
        // There is no combined sign / encrypt in gpgsm so we create one sign task
        // and one encrypt task. Which leaves us with the age old dilemma, encrypt
        // then sign, or sign then encrypt. Ugly.
        if (!cmsSigners.empty()) {
            result.push_back(
                createSignEncryptTaskForFileInfo(fi, ascii, std::vector<Key>(), cmsSigners, outputNames[SignEncryptFilesDialog::SignatureCMS], false));
        }
        if (!cmsRecipients.empty()) {
            result.push_back(
                createSignEncryptTaskForFileInfo(fi, ascii, cmsRecipients, std::vector<Key>(), outputNames[SignEncryptFilesDialog::EncryptedCMS], false));
        }
    }

    return result;
}

static std::vector<std::shared_ptr<SignEncryptTask>> createArchiveSignEncryptTasksForFiles(const QStringList &files,
                                                                                           const std::shared_ptr<ArchiveDefinition> &ad,
                                                                                           bool ascii,
                                                                                           const std::vector<Key> &pgpRecipients,
                                                                                           const std::vector<Key> &pgpSigners,
                                                                                           const std::vector<Key> &cmsRecipients,
                                                                                           const std::vector<Key> &cmsSigners,
                                                                                           const QMap<int, QString> &outputNames,
                                                                                           bool symmetric)
{
    std::vector<std::shared_ptr<SignEncryptTask>> result;

    const bool pgp = !pgpSigners.empty() || !pgpRecipients.empty();

    const bool cms = !cmsSigners.empty() || !cmsRecipients.empty();

    result.reserve(pgp + cms);

    if (pgp || symmetric) {
        int outKind = 0;
        if ((!pgpRecipients.empty() || symmetric) && !pgpSigners.empty()) {
            outKind = SignEncryptFilesDialog::CombinedPGP;
        } else if (!pgpRecipients.empty() || symmetric) {
            outKind = SignEncryptFilesDialog::EncryptedPGP;
        } else {
            outKind = SignEncryptFilesDialog::SignaturePGP;
        }
        result.push_back(createArchiveSignEncryptTaskForFiles(files, ad, true, ascii, pgpRecipients, pgpSigners, outputNames[outKind], symmetric));
    }
    if (cms) {
        if (!cmsSigners.empty()) {
            result.push_back(createArchiveSignEncryptTaskForFiles(files,
                                                                  ad,
                                                                  false,
                                                                  ascii,
                                                                  std::vector<Key>(),
                                                                  cmsSigners,
                                                                  outputNames[SignEncryptFilesDialog::SignatureCMS],
                                                                  false));
        }
        if (!cmsRecipients.empty()) {
            result.push_back(createArchiveSignEncryptTaskForFiles(files,
                                                                  ad,
                                                                  false,
                                                                  ascii,
                                                                  cmsRecipients,
                                                                  std::vector<Key>(),
                                                                  outputNames[SignEncryptFilesDialog::EncryptedCMS],
                                                                  false));
        }
    }

    return result;
}

namespace
{
static bool isDetachedOpenPGPSignature(const QString &fileName)
{
    const auto classification = Kleo::classify(fileName);
    return Kleo::isOpenPGP(classification) && Kleo::isDetachedSignature(classification);
}

static auto resolveFileNameConflicts(const std::vector<std::shared_ptr<SignEncryptTask>> &tasks, QWidget *parent)
{
    std::vector<std::shared_ptr<SignEncryptTask>> resolvedTasks;

    OverwritePolicy overwritePolicy{parent, tasks.size() > 1 ? OverwritePolicy::MultipleFiles : OverwritePolicy::Options{}};
    for (auto &task : tasks) {
        // by default, do not overwrite existing files
        task->setOverwritePolicy(std::make_shared<OverwritePolicy>(OverwritePolicy::Skip));
        const auto outputFileName = task->outputFileName();
        if (QFile::exists(outputFileName)) {
            const auto isDetachedOpenPGPSigningTask = (task->protocol() == GpgME::OpenPGP) && task->detachedSignatureEnabled();
            const auto extraOptions = (isDetachedOpenPGPSigningTask && isDetachedOpenPGPSignature(outputFileName) //
                                           ? OverwritePolicy::AllowAppend //
                                           : OverwritePolicy::Options{});
            const auto policyAndFileName = overwritePolicy.obtainOverwritePermission(outputFileName, extraOptions);
            if (policyAndFileName.policy == OverwritePolicy::Cancel) {
                resolvedTasks.clear();
                break;
            }
            switch (policyAndFileName.policy) {
            case OverwritePolicy::Skip:
                // do not add task to the final task list
                continue;
            case OverwritePolicy::Rename: {
                task->setOutputFileName(policyAndFileName.fileName);
                break;
            }
            case OverwritePolicy::Append: {
                task->setOverwritePolicy(std::make_shared<OverwritePolicy>(OverwritePolicy::Append));
                break;
            }
            case OverwritePolicy::Overwrite: {
                task->setOverwritePolicy(std::make_shared<OverwritePolicy>(OverwritePolicy::Overwrite));
                break;
            }
            case OverwritePolicy::Cancel:
                // already handled outside of switch
                break;
            case OverwritePolicy::None:
            case OverwritePolicy::Ask:
                qCDebug(KLEOPATRA_LOG) << "Unexpected OverwritePolicy result" << policyAndFileName.policy << "for" << outputFileName;
            };
        }
        resolvedTasks.push_back(task);
    }

    return resolvedTasks;
}
}

void SignEncryptFilesController::Private::slotWizardOperationPrepared()
{
    try {
        kleo_assert(wizard);
        kleo_assert(!files.empty());

        const bool archive = ((wizard->outputNames().value(SignEncryptFilesDialog::Directory).isNull() && files.size() > 1) //
                              || ((operation & ArchiveMask) == ArchiveForced));

        const std::vector<Key> recipients = wizard->resolvedRecipients();
        const std::vector<Key> signers = wizard->resolvedSigners();

        const FileOperationsPreferences prefs;
        const bool ascii = prefs.addASCIIArmor();

        std::vector<Key> pgpRecipients, cmsRecipients, pgpSigners, cmsSigners;
        for (const Key &k : recipients) {
            if (k.protocol() == GpgME::OpenPGP) {
                pgpRecipients.push_back(k);
            } else {
                cmsRecipients.push_back(k);
            }
        }

        for (const Key &k : signers) {
            if (k.protocol() == GpgME::OpenPGP) {
                pgpSigners.push_back(k);
            } else {
                cmsSigners.push_back(k);
            }
        }

        std::vector<std::shared_ptr<SignEncryptTask>> tasks;
        if (!archive) {
            tasks.reserve(files.size());
        }

        if (archive) {
            tasks = createArchiveSignEncryptTasksForFiles(files,
                                                          getDefaultAd(),
                                                          ascii,
                                                          pgpRecipients,
                                                          pgpSigners,
                                                          cmsRecipients,
                                                          cmsSigners,
                                                          wizard->outputNames(),
                                                          wizard->encryptSymmetric());
        } else {
            for (const QString &file : std::as_const(files)) {
                const std::vector<std::shared_ptr<SignEncryptTask>> created =
                    createSignEncryptTasksForFileInfo(QFileInfo(file),
                                                      ascii,
                                                      pgpRecipients,
                                                      pgpSigners,
                                                      cmsRecipients,
                                                      cmsSigners,
                                                      buildOutputNamesForDir(file, wizard->outputNames()),
                                                      wizard->encryptSymmetric());
                tasks.insert(tasks.end(), created.begin(), created.end());
            }
        }

        tasks = resolveFileNameConflicts(tasks, wizard);
        if (tasks.empty()) {
            q->cancel();
            return;
        }

        kleo_assert(runnable.empty());

        runnable.swap(tasks);

        for (const auto &task : std::as_const(runnable)) {
            q->connectTask(task);
        }

        std::shared_ptr<TaskCollection> coll(new TaskCollection);

        std::vector<std::shared_ptr<Task>> tmp;
        std::copy(runnable.begin(), runnable.end(), std::back_inserter(tmp));
        coll->setTasks(tmp);
        wizard->setTaskCollection(coll);

        QTimer::singleShot(0, q, SLOT(schedule()));

    } catch (const Kleo::Exception &e) {
        reportError(e.error().encodedError(), e.message());
    } catch (const std::exception &e) {
        reportError(
            gpg_error(GPG_ERR_UNEXPECTED),
            i18n("Caught unexpected exception in SignEncryptFilesController::Private::slotWizardOperationPrepared: %1", QString::fromLocal8Bit(e.what())));
    } catch (...) {
        reportError(gpg_error(GPG_ERR_UNEXPECTED), i18n("Caught unknown exception in SignEncryptFilesController::Private::slotWizardOperationPrepared"));
    }
}

void SignEncryptFilesController::Private::schedule()
{
    if (!cms)
        if (const std::shared_ptr<SignEncryptTask> t = takeRunnable(CMS)) {
            t->start();
            cms = t;
        }

    if (!openpgp)
        if (const std::shared_ptr<SignEncryptTask> t = takeRunnable(OpenPGP)) {
            t->start();
            openpgp = t;
        }

    if (!cms && !openpgp) {
        kleo_assert(runnable.empty());
        q->emitDoneOrError();
    }
}

std::shared_ptr<SignEncryptTask> SignEncryptFilesController::Private::takeRunnable(GpgME::Protocol proto)
{
    const auto it = std::find_if(runnable.begin(), runnable.end(), [proto](const std::shared_ptr<Task> &task) {
        return task->protocol() == proto;
    });
    if (it == runnable.end()) {
        return std::shared_ptr<SignEncryptTask>();
    }

    const std::shared_ptr<SignEncryptTask> result = *it;
    runnable.erase(it);
    return result;
}

void SignEncryptFilesController::doTaskDone(const Task *task, const std::shared_ptr<const Task::Result> &result)
{
    Q_UNUSED(result)
    Q_ASSERT(task);

    // We could just delete the tasks here, but we can't use
    // Qt::QueuedConnection here (we need sender()) and other slots
    // might not yet have executed. Therefore, we push completed tasks
    // into a burial container

    if (task == d->cms.get()) {
        d->completed.push_back(d->cms);
        d->cms.reset();
    } else if (task == d->openpgp.get()) {
        d->completed.push_back(d->openpgp);
        d->openpgp.reset();
    }

    QTimer::singleShot(0, this, SLOT(schedule()));
}

void SignEncryptFilesController::cancel()
{
    qCDebug(KLEOPATRA_LOG) << this << __func__;
    try {
        if (d->wizard) {
            d->wizard->close();
        }
        d->cancelAllTasks();
    } catch (const std::exception &e) {
        qCDebug(KLEOPATRA_LOG) << "Caught exception: " << e.what();
    }
}

void SignEncryptFilesController::Private::cancelAllTasks()
{
    // we just kill all runnable tasks - this will not result in
    // signal emissions.
    runnable.clear();

    // a cancel() will result in a call to
    if (cms) {
        cms->cancel();
    }
    if (openpgp) {
        openpgp->cancel();
    }
}

void SignEncryptFilesController::Private::ensureWizardCreated()
{
    if (wizard) {
        return;
    }

    std::unique_ptr<SignEncryptFilesDialog> w(new SignEncryptFilesDialog);
    w->setAttribute(Qt::WA_DeleteOnClose);

    connect(w.get(), SIGNAL(operationPrepared()), q, SLOT(slotWizardOperationPrepared()), Qt::QueuedConnection);
    connect(w.get(), SIGNAL(rejected()), q, SLOT(slotWizardCanceled()), Qt::QueuedConnection);
    wizard = w.release();

    updateWizardMode();
}

void SignEncryptFilesController::Private::ensureWizardVisible()
{
    ensureWizardCreated();
    q->bringToForeground(wizard);
}

#include "moc_signencryptfilescontroller.cpp"
