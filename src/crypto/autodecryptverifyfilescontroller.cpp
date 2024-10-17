/* -*- mode: c++; c-basic-offset:4 -*-
    autodecryptverifyfilescontroller.cpp

    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2008 Klarälvdalens Datakonsult AB

    SPDX-FileCopyrightText: 2016 Bundesamt für Sicherheit in der Informationstechnik
    SPDX-FileContributor: Intevation GmbH

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include <config-kleopatra.h>

#include "autodecryptverifyfilescontroller.h"

#include "fileoperationspreferences.h"

#include <crypto/decryptverifytask.h>
#include <crypto/gui/decryptverifyfilesdialog.h>
#include <crypto/gui/decryptverifyoperationwidget.h>
#include <crypto/taskcollection.h>

#include "commands/decryptverifyfilescommand.h"

#include <utils/archivedefinition.h>
#include <utils/input.h>
#include <utils/kleo_assert.h>
#include <utils/output.h>
#include <utils/overwritedialog.h>
#include <utils/path-helper.h>

#include <Libkleo/Algorithm>
#include <Libkleo/Classify>
#include <Libkleo/GnuPG>

#ifndef Q_OS_WIN
#include <KIO/CopyJob>
#include <KIO/Global>
#endif
#include "kleopatra_debug.h"
#include <KLocalizedString>
#include <KMessageBox>

#include <QGpgME/DecryptVerifyArchiveJob>

#include <QDir>
#include <QFile>
#include <QFileDialog>
#include <QFileInfo>
#include <QTemporaryDir>
#include <QTimer>

#include <gpgme++/decryptionresult.h>

using namespace GpgME;
using namespace Kleo;
using namespace Kleo::Crypto;
using namespace Kleo::Crypto::Gui;

class AutoDecryptVerifyFilesController::Private
{
    AutoDecryptVerifyFilesController *const q;

public:
    explicit Private(AutoDecryptVerifyFilesController *qq);

    void schedule();

    QString getEmbeddedFileName(const QString &fileName) const;
    void exec();
    std::vector<std::shared_ptr<Task>> buildTasks(const QStringList &, QStringList &);

    struct CryptoFile {
        QString baseName;
        QString fileName;
        GpgME::Protocol protocol = GpgME::UnknownProtocol;
        int classification = 0;
        std::shared_ptr<Output> output;
    };
    QList<CryptoFile> classifyAndSortFiles(const QStringList &files);

    void reportError(int err, const QString &details)
    {
        q->setLastError(err, details);
        q->emitDoneOrError();
    }
    void cancelAllTasks();
    void onDialogFinished(int result);

    QStringList m_passedFiles, m_filesAfterPreparation;
    std::vector<std::shared_ptr<const DecryptVerifyResult>> m_results;
    std::vector<std::shared_ptr<Task>> m_runnableTasks, m_completedTasks;
    std::shared_ptr<Task> m_runningTask;
    bool m_errorDetected = false;
    DecryptVerifyOperation m_operation = DecryptVerify;
    QPointer<DecryptVerifyFilesDialog> m_dialog;
    std::unique_ptr<QTemporaryDir> m_workDir;
};

AutoDecryptVerifyFilesController::Private::Private(AutoDecryptVerifyFilesController *qq)
    : q(qq)
{
    qRegisterMetaType<VerificationResult>();
}

void AutoDecryptVerifyFilesController::Private::schedule()
{
    if (!m_runningTask && !m_runnableTasks.empty()) {
        const std::shared_ptr<Task> t = m_runnableTasks.back();
        m_runnableTasks.pop_back();
        t->start();
        m_runningTask = t;
    }
    if (!m_runningTask) {
        kleo_assert(m_runnableTasks.empty());
        for (const std::shared_ptr<const DecryptVerifyResult> &i : std::as_const(m_results)) {
            Q_EMIT q->verificationResult(i->verificationResult());
        }
    }
}

QString AutoDecryptVerifyFilesController::Private::getEmbeddedFileName(const QString &fileName) const
{
    auto it = std::find_if(m_results.cbegin(), m_results.cend(), [fileName](const auto &r) {
        return r->fileName() == fileName;
    });
    if (it != m_results.cend()) {
        const auto embeddedFilePath = QString::fromUtf8((*it)->decryptionResult().fileName());
        if (embeddedFilePath.contains(QLatin1Char{'\\'})) {
            // ignore embedded file names containing '\'
            return {};
        }
        // strip the path from the embedded file name
        return QFileInfo{embeddedFilePath}.fileName();
    } else {
        return {};
    }
}

void AutoDecryptVerifyFilesController::Private::exec()
{
    Q_ASSERT(!m_dialog);

    QStringList undetected;
    std::vector<std::shared_ptr<Task>> tasks = buildTasks(m_passedFiles, undetected);

    if (!undetected.isEmpty()) {
        // Since GpgME 1.7.0 Classification is supposed to be reliable
        // so we really can't do anything with this data.
        reportError(makeGnuPGError(GPG_ERR_GENERAL),
                    xi18nc("@info",
                           "Failed to find encrypted or signed data in one or more files.<nl/>"
                           "You can manually select what to do with the files now.<nl/>"
                           "If they contain signed or encrypted data please report a bug (see Help->Report Bug)."));
        auto cmd = new Commands::DecryptVerifyFilesCommand(undetected, nullptr, true);
        cmd->start();
    }
    if (tasks.empty()) {
        q->emitDoneOrError();
        return;
    }
    Q_ASSERT(m_runnableTasks.empty());
    m_runnableTasks.swap(tasks);

    std::shared_ptr<TaskCollection> coll(new TaskCollection);
    for (const std::shared_ptr<Task> &i : std::as_const(m_runnableTasks)) {
        q->connectTask(i);
    }
    coll->setTasks(m_runnableTasks);
    m_dialog = new DecryptVerifyFilesDialog(coll);
    m_dialog->setAttribute(Qt::WA_DeleteOnClose);
    m_dialog->setOutputLocation(heuristicBaseDirectory(m_passedFiles));
    q->applyWindowID(m_dialog);

    m_dialog->show();
    QTimer::singleShot(0, q, SLOT(schedule()));
    connect(m_dialog, &QDialog::finished, q, [this](auto result) {
        onDialogFinished(result);
    });
}

QList<AutoDecryptVerifyFilesController::Private::CryptoFile> AutoDecryptVerifyFilesController::Private::classifyAndSortFiles(const QStringList &files)
{
    const auto isSignature = [](int classification) -> bool {
        return mayBeDetachedSignature(classification) //
            || mayBeOpaqueSignature(classification) //
            || (classification & Class::TypeMask) == Class::ClearsignedMessage;
    };

    QList<CryptoFile> out;
    for (const auto &file : files) {
        CryptoFile cFile;
        cFile.fileName = file;
        cFile.baseName = stripSuffix(file);
        cFile.classification = classify(file);
        cFile.protocol = findProtocol(cFile.classification);

        auto it = std::find_if(out.begin(), out.end(), [&cFile](const CryptoFile &other) {
            return other.protocol == cFile.protocol && other.baseName == cFile.baseName;
        });
        if (it != out.end()) {
            // If we found a file with the same basename, make sure that encrypted
            // file is before the signature file, so that we first decrypt and then
            // verify
            if (isSignature(cFile.classification) && isCipherText(it->classification)) {
                out.insert(it + 1, cFile);
            } else if (isCipherText(cFile.classification) && isSignature(it->classification)) {
                out.insert(it, cFile);
            } else {
                // both are signatures or both are encrypted files, in which
                // case order does not matter
                out.insert(it, cFile);
            }
        } else {
            out.push_back(cFile);
        }
    }

    return out;
}

static bool archiveJobsCanBeUsed([[maybe_unused]] GpgME::Protocol protocol)
{
    return (protocol == GpgME::OpenPGP) && QGpgME::DecryptVerifyArchiveJob::isSupported();
}

std::vector<std::shared_ptr<Task>> AutoDecryptVerifyFilesController::Private::buildTasks(const QStringList &fileNames, QStringList &undetected)
{
    // sort files so that we make sure we first decrypt and then verify
    QList<CryptoFile> cryptoFiles = classifyAndSortFiles(fileNames);

    std::vector<std::shared_ptr<Task>> tasks;
    for (auto it = cryptoFiles.begin(), end = cryptoFiles.end(); it != end; ++it) {
        auto &cFile = (*it);
        QFileInfo fi(cFile.fileName);
        qCDebug(KLEOPATRA_LOG) << "classified" << cFile.fileName << "as" << printableClassification(cFile.classification);

        if (!fi.isReadable()) {
            reportError(makeGnuPGError(GPG_ERR_ASS_NO_INPUT), xi18nc("@info", "Cannot open <filename>%1</filename> for reading.", cFile.fileName));
            continue;
        }

        if (mayBeAnyCertStoreType(cFile.classification)) {
            // Trying to verify a certificate. Possible because extensions are often similar
            // for PGP Keys.
            reportError(makeGnuPGError(GPG_ERR_ASS_NO_INPUT),
                        xi18nc("@info", "The file <filename>%1</filename> contains certificates and can't be decrypted or verified.", cFile.fileName));
            qCDebug(KLEOPATRA_LOG) << "reported error";
            continue;
        }

        // We can't reliably detect CMS detached signatures, so we will try to do
        // our best to use the current file as a detached signature and fallback to
        // opaque signature otherwise.
        if (cFile.protocol == GpgME::CMS && mayBeDetachedSignature(cFile.classification)) {
            // First, see if previous task was a decryption task for the same file
            // and "pipe" it's output into our input
            std::shared_ptr<Input> input;
            bool prepend = false;
            if (it != cryptoFiles.begin()) {
                const auto prev = it - 1;
                if (prev->protocol == cFile.protocol && prev->baseName == cFile.baseName) {
                    input = Input::createFromOutput(prev->output);
                    prepend = true;
                }
            }

            if (!input) {
                if (QFile::exists(cFile.baseName)) {
                    input = Input::createFromFile(cFile.baseName);
                }
            }

            if (input) {
                qCDebug(KLEOPATRA_LOG) << "Detached CMS verify: " << cFile.fileName;
                std::shared_ptr<VerifyDetachedTask> t(new VerifyDetachedTask);
                t->setInput(Input::createFromFile(cFile.fileName));
                t->setSignedData(input);
                t->setProtocol(cFile.protocol);
                if (prepend) {
                    // Put the verify task BEFORE the decrypt task in the tasks queue,
                    // because the tasks are executed in reverse order!
                    tasks.insert(tasks.end() - 1, t);
                } else {
                    tasks.push_back(t);
                }
                continue;
            } else {
                // No signed data, maybe not a detached signature
            }
        }

        if (isDetachedSignature(cFile.classification)) {
            // Detached signature, try to find data or ask the user.
            QString signedDataFileName = cFile.baseName;
            if (!QFile::exists(signedDataFileName)) {
                signedDataFileName =
                    QFileDialog::getOpenFileName(nullptr,
                                                 xi18nc("@title:window", "Select the file to verify with the signature <filename>%1</filename>", fi.fileName()),
                                                 fi.path());
            }
            if (signedDataFileName.isEmpty()) {
                qCDebug(KLEOPATRA_LOG) << "No signed data selected. Verify aborted.";
            } else {
                qCDebug(KLEOPATRA_LOG) << "Detached verify: " << cFile.fileName << " Data: " << signedDataFileName;
                std::shared_ptr<VerifyDetachedTask> t(new VerifyDetachedTask);
#if QGPGME_FILE_JOBS_SUPPORT_DIRECT_FILE_IO
                if (cFile.protocol == GpgME::OpenPGP) {
                    t->setSignatureFile(cFile.fileName);
                    t->setSignedFile(signedDataFileName);
                } else {
                    t->setInput(Input::createFromFile(cFile.fileName));
                    t->setSignedData(Input::createFromFile(signedDataFileName));
                }
#else
                t->setInput(Input::createFromFile(cFile.fileName));
                t->setSignedData(Input::createFromFile(signedDataFileName));
#endif
                t->setProtocol(cFile.protocol);
                tasks.push_back(t);
            }
            continue;
        }

        if (!mayBeAnyMessageType(cFile.classification)) {
            // Not a Message? Maybe there is a signature for this file?
            const auto signatures = findSignatures(cFile.fileName);
            bool foundSig = false;
            if (!signatures.empty()) {
                for (const QString &sig : signatures) {
                    const auto classification = classify(sig);
                    qCDebug(KLEOPATRA_LOG) << "Guessing: " << sig << " is a signature for: " << cFile.fileName << "Classification: " << classification;
                    const auto proto = findProtocol(classification);
                    if (proto == GpgME::UnknownProtocol) {
                        qCDebug(KLEOPATRA_LOG) << "Could not determine protocol. Skipping guess.";
                        continue;
                    }
                    foundSig = true;
                    std::shared_ptr<VerifyDetachedTask> t(new VerifyDetachedTask);
#if QGPGME_FILE_JOBS_SUPPORT_DIRECT_FILE_IO
                    if (cFile.protocol == GpgME::OpenPGP) {
                        t->setSignatureFile(sig);
                        t->setSignedFile(cFile.fileName);
                    } else {
                        t->setInput(Input::createFromFile(sig));
                        t->setSignedData(Input::createFromFile(cFile.fileName));
                    }
#else
                    t->setInput(Input::createFromFile(sig));
                    t->setSignedData(Input::createFromFile(cFile.fileName));
#endif
                    t->setProtocol(proto);
                    tasks.push_back(t);
                }
            }
            if (!foundSig) {
                undetected << cFile.fileName;
                qCDebug(KLEOPATRA_LOG) << "Failed detection for: " << cFile.fileName << " adding to undetected.";
            }
        } else {
            const FileOperationsPreferences fileOpSettings;
            // Any Message type so we have input and output.
            std::shared_ptr<Input> input;
#if QGPGME_FILE_JOBS_SUPPORT_DIRECT_FILE_IO
            if (cFile.protocol != GpgME::OpenPGP) {
                input = Input::createFromFile(cFile.fileName);
            }
#else
            input = Input::createFromFile(cFile.fileName);
#endif

            std::shared_ptr<ArchiveDefinition> ad;
            if (fileOpSettings.autoExtractArchives()) {
                const auto archiveDefinitions = ArchiveDefinition::getArchiveDefinitions();
                ad = q->pick_archive_definition(cFile.protocol, archiveDefinitions, cFile.fileName);
            }

            if (fileOpSettings.dontUseTmpDir()) {
                if (!m_workDir) {
                    m_workDir = std::make_unique<QTemporaryDir>(heuristicBaseDirectory(fileNames) + QStringLiteral("/kleopatra-XXXXXX"));
                }
                if (!m_workDir->isValid()) {
                    qCDebug(KLEOPATRA_LOG) << heuristicBaseDirectory(fileNames) << "not a valid temporary directory.";
                    m_workDir.reset();
                }
            }
            if (!m_workDir) {
                m_workDir = std::make_unique<QTemporaryDir>();
            }
            qCDebug(KLEOPATRA_LOG) << "Using:" << m_workDir->path() << "as temporary directory.";

            const auto wd = QDir(m_workDir->path());

            std::shared_ptr<Output> output;
            QString outputFilePath;
            if (ad) {
                if ((ad->id() == QLatin1StringView{"tar"}) && archiveJobsCanBeUsed(cFile.protocol)) {
                    // we don't need an output
                } else {
                    output = ad->createOutputFromUnpackCommand(cFile.protocol, ad->stripExtension(cFile.protocol, cFile.baseName), wd);
                }
            } else {
                outputFilePath = wd.absoluteFilePath(outputFileName(fi.fileName()));
#if QGPGME_FILE_JOBS_SUPPORT_DIRECT_FILE_IO
                if (cFile.protocol != GpgME::OpenPGP) {
                    output = Output::createFromFile(outputFilePath, false);
                }
#else
                output = Output::createFromFile(outputFilePath, false);
#endif
            }

            // If this might be opaque CMS signature, then try that. We already handled
            // detached CMS signature above
            const auto isCMSOpaqueSignature = cFile.protocol == GpgME::CMS && mayBeOpaqueSignature(cFile.classification);

            if (isOpaqueSignature(cFile.classification) || isCMSOpaqueSignature) {
                qCDebug(KLEOPATRA_LOG) << "creating a VerifyOpaqueTask";
                std::shared_ptr<VerifyOpaqueTask> t(new VerifyOpaqueTask);
                if (input) {
                    t->setInput(input);
                }
                if (output) {
                    t->setOutput(output);
                }
                t->setProtocol(cFile.protocol);
                if (ad) {
                    t->setExtractArchive(true);
                    t->setInputFile(cFile.fileName);
                    if (output) {
                        t->setOutputDirectory(m_workDir->path());
                    } else {
                        // make gpgtar extract to a subfolder of the work directory based on the input file name
                        const auto baseFileName = QFileInfo{ad->stripExtension(cFile.protocol, cFile.baseName)}.fileName();
                        t->setOutputDirectory(QDir{m_workDir->path()}.filePath(baseFileName));
                    }
#if QGPGME_FILE_JOBS_SUPPORT_DIRECT_FILE_IO
                } else if (cFile.protocol == GpgME::OpenPGP) {
                    t->setInputFile(cFile.fileName);
                    t->setOutputFile(outputFilePath);
#endif
                }
                tasks.push_back(t);
            } else {
                // Any message. That is not an opaque signature needs to be
                // decrypted. Verify we always do because we can't know if
                // an encrypted message is also signed.
                qCDebug(KLEOPATRA_LOG) << "creating a DecryptVerifyTask";
                std::shared_ptr<DecryptVerifyTask> t(new DecryptVerifyTask);
                if (input) {
                    t->setInput(input);
                }
                if (output) {
                    t->setOutput(output);
                }
                t->setProtocol(cFile.protocol);
                if (ad) {
                    t->setExtractArchive(true);
                    t->setInputFile(cFile.fileName);
                    if (output) {
                        t->setOutputDirectory(m_workDir->path());
                    } else {
                        // make gpgtar extract to a subfolder of the work directory based on the input file name
                        const auto baseFileName = QFileInfo{ad->stripExtension(cFile.protocol, cFile.baseName)}.fileName();
                        t->setOutputDirectory(QDir{m_workDir->path()}.filePath(baseFileName));
                    }
#if QGPGME_FILE_JOBS_SUPPORT_DIRECT_FILE_IO
                } else if (cFile.protocol == GpgME::OpenPGP) {
                    t->setInputFile(cFile.fileName);
                    t->setOutputFile(outputFilePath);
#endif
                }
                cFile.output = output;
                tasks.push_back(t);
            }
        }
    }

    return tasks;
}

void AutoDecryptVerifyFilesController::setFiles(const QStringList &files)
{
    d->m_passedFiles = files;
}

AutoDecryptVerifyFilesController::AutoDecryptVerifyFilesController(QObject *parent)
    : DecryptVerifyFilesController(parent)
    , d(new Private(this))
{
}

AutoDecryptVerifyFilesController::AutoDecryptVerifyFilesController(const std::shared_ptr<const ExecutionContext> &ctx, QObject *parent)
    : DecryptVerifyFilesController(ctx, parent)
    , d(new Private(this))
{
}

AutoDecryptVerifyFilesController::~AutoDecryptVerifyFilesController()
{
    qCDebug(KLEOPATRA_LOG);
}

void AutoDecryptVerifyFilesController::start()
{
    d->exec();
}

void AutoDecryptVerifyFilesController::setOperation(DecryptVerifyOperation op)
{
    d->m_operation = op;
}

DecryptVerifyOperation AutoDecryptVerifyFilesController::operation() const
{
    return d->m_operation;
}

void AutoDecryptVerifyFilesController::Private::cancelAllTasks()
{
    // we just kill all runnable tasks - this will not result in
    // signal emissions.
    m_runnableTasks.clear();

    // a cancel() will result in a call to
    if (m_runningTask) {
        m_runningTask->cancel();
    }
}

void AutoDecryptVerifyFilesController::cancel()
{
    qCDebug(KLEOPATRA_LOG) << this << __func__;
    try {
        d->m_errorDetected = true;
        if (d->m_dialog) {
            d->m_dialog->close();
        }
        d->cancelAllTasks();
    } catch (const std::exception &e) {
        qCDebug(KLEOPATRA_LOG) << "Caught exception: " << e.what();
    }
}

void AutoDecryptVerifyFilesController::doTaskDone(const Task *task, const std::shared_ptr<const Task::Result> &result)
{
    Q_ASSERT(task);
    Q_UNUSED(task)

    // We could just delete the tasks here, but we can't use
    // Qt::QueuedConnection here (we need sender()) and other slots
    // might not yet have executed. Therefore, we push completed tasks
    // into a burial container

    d->m_completedTasks.push_back(d->m_runningTask);
    d->m_runningTask.reset();

    if (const std::shared_ptr<const DecryptVerifyResult> &dvr = std::dynamic_pointer_cast<const DecryptVerifyResult>(result)) {
        d->m_results.push_back(dvr);
    }

    QTimer::singleShot(0, this, SLOT(schedule()));
}

void AutoDecryptVerifyFilesController::Private::onDialogFinished(int result)
{
    if (result == QDialog::Rejected) {
        q->cancel();
    } else if (result == QDialog::Accepted && m_workDir) {
        // Without workdir there is nothing to move.
        const QDir workdir(m_workDir->path());
        const QDir outDir(m_dialog->outputLocation());
        qCDebug(KLEOPATRA_LOG) << workdir.entryList(QDir::Files | QDir::Dirs | QDir::NoDotAndDotDot);
        const auto filesAndFoldersToMove = workdir.entryInfoList(QDir::Files | QDir::Dirs | QDir::NoDotAndDotDot);
        const auto fileCount = Kleo::count_if(filesAndFoldersToMove, [](const auto &fi) {
            return !fi.isDir();
        });
        OverwritePolicy overwritePolicy{m_dialog, fileCount > 1 ? OverwritePolicy::MultipleFiles : OverwritePolicy::Options{}};
        for (const QFileInfo &fi : filesAndFoldersToMove) {
            const auto inpath = fi.absoluteFilePath();

            if (fi.isDir()) {
                // A directory. Assume that the input was an archive
                // and avoid directory merges by trying to find a non
                // existing directory.
                auto candidate = fi.fileName();
                if (candidate.startsWith(QLatin1Char('-'))) {
                    // Bug in GpgTar Extracts stdout passed archives to a dir named -
                    candidate = QFileInfo(m_passedFiles.first()).baseName();
                }

                QString suffix;
                QFileInfo ofi;
                int i = 0;
                do {
                    ofi = QFileInfo(outDir.absoluteFilePath(candidate + suffix));
                    if (!ofi.exists()) {
                        break;
                    }
                    suffix = QStringLiteral("_%1").arg(++i);
                } while (i < 1000);

                const auto destPath = ofi.absoluteFilePath();
#ifndef Q_OS_WIN
                auto job = KIO::moveAs(QUrl::fromLocalFile(inpath), QUrl::fromLocalFile(destPath));
                qCDebug(KLEOPATRA_LOG) << "Moving" << job->srcUrls().front().toLocalFile() << "to" << job->destUrl().toLocalFile();
                if (!job->exec()) {
                    if (job->error() == KIO::ERR_USER_CANCELED) {
                        break;
                    }
                    reportError(makeGnuPGError(GPG_ERR_GENERAL),
                                xi18nc("@info",
                                       "<para>Failed to move <filename>%1</filename> to <filename>%2</filename>.</para>"
                                       "<para><message>%3</message></para>",
                                       inpath,
                                       destPath,
                                       job->errorString()));
                }
#else
                // On Windows, KIO::move does not work for folders when crossing partition boundaries
                if (!moveDir(inpath, destPath)) {
                    reportError(makeGnuPGError(GPG_ERR_GENERAL),
                                xi18nc("@info", "<para>Failed to move <filename>%1</filename> to <filename>%2</filename>.</para>", inpath, destPath));
                }
#endif
                continue;
            }

            const auto embeddedFileName = getEmbeddedFileName(inpath);
            QString outFileName = fi.fileName();
            if (!embeddedFileName.isEmpty() && embeddedFileName != fi.fileName()) {
                // we switch "Yes" and "No" because Yes is default, but saving with embedded file name could be dangerous
                const auto answer = KMessageBox::questionTwoActionsCancel(
                    m_dialog,
                    xi18nc("@info", "Shall the file be saved with the original file name <filename>%1</filename>?", embeddedFileName),
                    i18nc("@title:window", "Use Original File Name?"),
                    KGuiItem(xi18nc("@action:button", "No, Save As <filename>%1</filename>", fi.fileName())),
                    KGuiItem(xi18nc("@action:button", "Yes, Save As <filename>%1</filename>", embeddedFileName)));
                if (answer == KMessageBox::Cancel) {
                    qCDebug(KLEOPATRA_LOG) << "Saving canceled for:" << inpath;
                    continue;
                } else if (answer == KMessageBox::ButtonCode::SecondaryAction) {
                    outFileName = embeddedFileName;
                }
            }
            auto outpath = outDir.absoluteFilePath(outFileName);
            qCDebug(KLEOPATRA_LOG) << "Moving " << inpath << " to " << outpath;
            const QFileInfo ofi(outpath);
            if (ofi.exists()) {
                const auto policyAndPath = overwritePolicy.obtainOverwritePermission(outpath);
                if (policyAndPath.policy == OverwritePolicy::Cancel) {
                    qCDebug(KLEOPATRA_LOG) << "Overwriting canceled for: " << outpath;
                    break;
                }
                switch (policyAndPath.policy) {
                case OverwritePolicy::Skip:
                    continue;
                case OverwritePolicy::Overwrite: {
                    // overwrite existing file
                    if (!QFile::remove(outpath)) {
                        reportError(makeGnuPGError(GPG_ERR_GENERAL), xi18nc("@info", "Failed to delete <filename>%1</filename>.", outpath));
                        continue;
                    }
                    break;
                }
                case OverwritePolicy::Rename: {
                    // use new name for file
                    outpath = policyAndPath.fileName;
                    break;
                }
                case OverwritePolicy::Cancel:
                    // already handled outside of switch
                    break;
                case OverwritePolicy::None:
                case OverwritePolicy::Ask:
                case OverwritePolicy::Append:
                    qCDebug(KLEOPATRA_LOG) << "Unexpected OverwritePolicy result" << policyAndPath.policy << "for" << outpath;
                };
            }
            if (!QFile::rename(inpath, outpath)) {
                reportError(makeGnuPGError(GPG_ERR_GENERAL),
                            xi18nc("@info", "Failed to move <filename>%1</filename> to <filename>%2</filename>.", inpath, outpath));
            }
        }
    }
    q->emitDoneOrError();
}

#include "moc_autodecryptverifyfilescontroller.cpp"
