/* -*- mode: c++; c-basic-offset:4 -*-
    decryptverifyfilescontroller.cpp

    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2008 Klarälvdalens Datakonsult AB

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include <config-kleopatra.h>

#include "decryptverifyfilescontroller.h"

#include <crypto/decryptverifytask.h>
#include <crypto/gui/decryptverifyfileswizard.h>
#include <crypto/gui/decryptverifyoperationwidget.h>
#include <crypto/taskcollection.h>

#include <Libkleo/GnuPG>
#include <utils/archivedefinition.h>
#include <utils/input.h>
#include <utils/kleo_assert.h>
#include <utils/output.h>
#include <utils/path-helper.h>

#include <Libkleo/Classify>

#include "kleopatra_debug.h"
#include <KLocalizedString>

#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QPointer>
#include <QTimer>

using namespace GpgME;
using namespace Kleo;
using namespace Kleo::Crypto;
using namespace Kleo::Crypto::Gui;

class DecryptVerifyFilesController::Private
{
    DecryptVerifyFilesController *const q;

public:
    static std::shared_ptr<AbstractDecryptVerifyTask> taskFromOperationWidget(const DecryptVerifyOperationWidget *w,
                                                                              const QString &fileName,
                                                                              const QDir &outDir,
                                                                              const std::shared_ptr<OverwritePolicy> &overwritePolicy);

    explicit Private(DecryptVerifyFilesController *qq);

    void slotWizardOperationPrepared();
    void slotWizardCanceled();
    void schedule();

    void prepareWizardFromPassedFiles();
    std::vector<std::shared_ptr<Task>> buildTasks(const QStringList &, const std::shared_ptr<OverwritePolicy> &);

    void ensureWizardCreated();
    void ensureWizardVisible();
    void reportError(int err, const QString &details)
    {
        q->setLastError(err, details);
        q->emitDoneOrError();
    }
    void cancelAllTasks();

    QStringList m_passedFiles, m_filesAfterPreparation;
    QPointer<DecryptVerifyFilesWizard> m_wizard;
    std::vector<std::shared_ptr<const DecryptVerifyResult>> m_results;
    std::vector<std::shared_ptr<Task>> m_runnableTasks, m_completedTasks;
    std::shared_ptr<Task> m_runningTask;
    bool m_errorDetected;
    DecryptVerifyOperation m_operation;
};

// static
std::shared_ptr<AbstractDecryptVerifyTask>
DecryptVerifyFilesController::Private::taskFromOperationWidget(const DecryptVerifyOperationWidget *w,
                                                               const QString &fileName,
                                                               const QDir &outDir,
                                                               const std::shared_ptr<OverwritePolicy> &overwritePolicy)
{
    kleo_assert(w);
    qWarning() << "B" << fileName << outDir;

    std::shared_ptr<AbstractDecryptVerifyTask> task;

    switch (w->mode()) {
    case DecryptVerifyOperationWidget::VerifyDetachedWithSignature: {
        std::shared_ptr<VerifyDetachedTask> t(new VerifyDetachedTask);
        t->setInput(Input::createFromFile(fileName));
        t->setSignedData(Input::createFromFile(w->signedDataFileName()));
        task = t;

        kleo_assert(fileName == w->inputFileName());
    } break;
    case DecryptVerifyOperationWidget::VerifyDetachedWithSignedData: {
        std::shared_ptr<VerifyDetachedTask> t(new VerifyDetachedTask);
        t->setInput(Input::createFromFile(w->inputFileName()));
        t->setSignedData(Input::createFromFile(fileName));
        task = t;

        kleo_assert(fileName == w->signedDataFileName());
    } break;
    case DecryptVerifyOperationWidget::DecryptVerifyOpaque: {
        const unsigned int classification = classify(fileName);
        qCDebug(KLEOPATRA_LOG) << "classified" << fileName << "as" << printableClassification(classification);

        const std::shared_ptr<ArchiveDefinition> ad = w->selectedArchiveDefinition();

        const Protocol proto = isOpenPGP(classification) ? OpenPGP
            : isCMS(classification)                      ? CMS
            : ad ? throw Exception(gpg_error(GPG_ERR_CONFLICT), i18n("Cannot determine whether input data is OpenPGP or CMS"))
                 : UnknownProtocol;

        const std::shared_ptr<Input> input = Input::createFromFile(fileName);
        const std::shared_ptr<Output> output = ad
            ? ad->createOutputFromUnpackCommand(proto, fileName, outDir)
            : Output::createFromFile(outDir.absoluteFilePath(outputFileName(QFileInfo(fileName).fileName())), overwritePolicy);

        if (mayBeCipherText(classification)) {
            qCDebug(KLEOPATRA_LOG) << "creating a DecryptVerifyTask";
            std::shared_ptr<DecryptVerifyTask> t(new DecryptVerifyTask);
            t->setInput(input);
            t->setOutput(output);
            task = t;
        } else {
            qCDebug(KLEOPATRA_LOG) << "creating a VerifyOpaqueTask";
            std::shared_ptr<VerifyOpaqueTask> t(new VerifyOpaqueTask);
            t->setInput(input);
            t->setOutput(output);
            task = t;
        }

        kleo_assert(fileName == w->inputFileName());
    } break;
    }

    task->autodetectProtocolFromInput();
    return task;
}

DecryptVerifyFilesController::Private::Private(DecryptVerifyFilesController *qq)
    : q(qq)
    , m_errorDetected(false)
    , m_operation(DecryptVerify)
{
    qRegisterMetaType<VerificationResult>();
}

void DecryptVerifyFilesController::Private::slotWizardOperationPrepared()
{
    ensureWizardCreated();
    std::vector<std::shared_ptr<Task>> tasks = buildTasks(m_filesAfterPreparation, std::make_shared<OverwritePolicy>(m_wizard, OverwritePolicy::MultipleFiles));
    if (tasks.empty()) {
        reportError(makeGnuPGError(GPG_ERR_ASS_NO_INPUT), i18n("No usable inputs found"));
    }
    kleo_assert(m_runnableTasks.empty());
    m_runnableTasks.swap(tasks);

    std::shared_ptr<TaskCollection> coll(new TaskCollection);
    for (const auto &i : m_runnableTasks) {
        q->connectTask(i);
    }
    coll->setTasks(m_runnableTasks);
    m_wizard->setTaskCollection(coll);

    QTimer::singleShot(0, q, SLOT(schedule()));
}

void DecryptVerifyFilesController::Private::slotWizardCanceled()
{
    qCDebug(KLEOPATRA_LOG) << this << __func__;
    q->cancel();
    q->emitDoneOrError();
}

void DecryptVerifyFilesController::doTaskDone(const Task *task, const std::shared_ptr<const Task::Result> &result)
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

void DecryptVerifyFilesController::Private::schedule()
{
    if (!m_runningTask && !m_runnableTasks.empty()) {
        const std::shared_ptr<Task> t = m_runnableTasks.back();
        m_runnableTasks.pop_back();
        t->start();
        m_runningTask = t;
    }
    if (!m_runningTask) {
        kleo_assert(m_runnableTasks.empty());
        for (const auto &i : m_results) {
            Q_EMIT q->verificationResult(i->verificationResult());
        }
        q->emitDoneOrError();
    }
}

void DecryptVerifyFilesController::Private::ensureWizardCreated()
{
    if (m_wizard) {
        return;
    }

    std::unique_ptr<DecryptVerifyFilesWizard> w(new DecryptVerifyFilesWizard);
    w->setWindowTitle(i18nc("@title:window", "Decrypt/Verify Files"));
    w->setAttribute(Qt::WA_DeleteOnClose);

    connect(w.get(), SIGNAL(operationPrepared()), q, SLOT(slotWizardOperationPrepared()), Qt::QueuedConnection);
    connect(w.get(), SIGNAL(canceled()), q, SLOT(slotWizardCanceled()), Qt::QueuedConnection);
    m_wizard = w.release();
}

namespace
{
struct FindExtension {
    const QString ext;
    const Protocol proto;
    FindExtension(const QString &ext, Protocol proto)
        : ext(ext)
        , proto(proto)
    {
    }
    bool operator()(const std::shared_ptr<ArchiveDefinition> &ad) const
    {
        qCDebug(KLEOPATRA_LOG) << "   considering" << (ad ? ad->label() : QStringLiteral("<null>")) << "for" << ext;
        bool result;
        if (proto == UnknownProtocol) {
            result = ad && (ad->extensions(OpenPGP).contains(ext, Qt::CaseInsensitive) || ad->extensions(CMS).contains(ext, Qt::CaseInsensitive));
        } else {
            result = ad && ad->extensions(proto).contains(ext, Qt::CaseInsensitive);
        }
        qCDebug(KLEOPATRA_LOG) << (result ? "   -> matches" : "   -> doesn't match");
        return result;
    }
};
}

std::shared_ptr<ArchiveDefinition> DecryptVerifyFilesController::pick_archive_definition(GpgME::Protocol proto,
                                                                                         const std::vector<std::shared_ptr<ArchiveDefinition>> &ads,
                                                                                         const QString &filename)
{
    const QFileInfo fi(outputFileName(filename));
    QString extension = fi.completeSuffix();

    if (extension == QLatin1StringView("out")) { // added by outputFileName() -> useless
        return std::shared_ptr<ArchiveDefinition>();
    }

    if (extension.endsWith(QLatin1StringView(".out"))) { // added by outputFileName() -> remove
        extension.chop(4);
    }

    for (;;) {
        const auto it = std::find_if(ads.begin(), ads.end(), FindExtension(extension, proto));
        if (it != ads.end()) {
            return *it;
        }
        const int idx = extension.indexOf(QLatin1Char('.'));
        if (idx < 0) {
            return std::shared_ptr<ArchiveDefinition>();
        }
        extension = extension.mid(idx + 1);
    }
}

void DecryptVerifyFilesController::Private::prepareWizardFromPassedFiles()
{
    ensureWizardCreated();
    const std::vector<std::shared_ptr<ArchiveDefinition>> archiveDefinitions = ArchiveDefinition::getArchiveDefinitions();

    unsigned int counter = 0;
    for (const auto &fname : std::as_const(m_passedFiles)) {
        kleo_assert(!fname.isEmpty());

        const unsigned int classification = classify(fname);
        const Protocol proto = findProtocol(classification);

        if (mayBeOpaqueSignature(classification) || mayBeCipherText(classification) || mayBeDetachedSignature(classification)) {
            DecryptVerifyOperationWidget *const op = m_wizard->operationWidget(counter++);
            kleo_assert(op != nullptr);

            op->setArchiveDefinitions(archiveDefinitions);

            const QString signedDataFileName = findSignedData(fname);

            // this breaks opaque signatures whose source files still
            // happen to exist in the same directory. Until we have
            // content-based classification, this is the most unlikely
            // case, so that's the case we break. ### FIXME remove when content-classify is done
            if (mayBeDetachedSignature(classification) && !signedDataFileName.isEmpty()) {
                op->setMode(DecryptVerifyOperationWidget::VerifyDetachedWithSignature);
            }
            // ### end FIXME
            else if (mayBeOpaqueSignature(classification) || mayBeCipherText(classification)) {
                op->setMode(DecryptVerifyOperationWidget::DecryptVerifyOpaque, q->pick_archive_definition(proto, archiveDefinitions, fname));
            } else {
                op->setMode(DecryptVerifyOperationWidget::VerifyDetachedWithSignature);
            }

            op->setInputFileName(fname);
            op->setSignedDataFileName(signedDataFileName);

            m_filesAfterPreparation << fname;

        } else {
            // probably the signed data file was selected:
            const QStringList signatures = findSignatures(fname);

            if (signatures.empty()) {
                // We are assuming this is a detached signature file, but
                // there were no signature files for it. Let's guess it's encrypted after all.
                // ### FIXME once we have a proper heuristic for this, this should move into
                // classify() and/or classifyContent()
                DecryptVerifyOperationWidget *const op = m_wizard->operationWidget(counter++);
                kleo_assert(op != nullptr);
                op->setArchiveDefinitions(archiveDefinitions);
                op->setMode(DecryptVerifyOperationWidget::DecryptVerifyOpaque, q->pick_archive_definition(proto, archiveDefinitions, fname));
                op->setInputFileName(fname);
                m_filesAfterPreparation << fname;
            } else {
                for (const auto &s : signatures) {
                    DecryptVerifyOperationWidget *op = m_wizard->operationWidget(counter++);
                    kleo_assert(op != nullptr);

                    op->setArchiveDefinitions(archiveDefinitions);
                    op->setMode(DecryptVerifyOperationWidget::VerifyDetachedWithSignedData);
                    op->setInputFileName(s);
                    op->setSignedDataFileName(fname);

                    m_filesAfterPreparation << fname;
                }
            }
        }
    }

    m_wizard->setOutputDirectory(heuristicBaseDirectory(m_passedFiles));
    return;
}

std::vector<std::shared_ptr<Task>> DecryptVerifyFilesController::Private::buildTasks(const QStringList &fileNames,
                                                                                     const std::shared_ptr<OverwritePolicy> &overwritePolicy)
{
    const bool useOutDir = m_wizard->useOutputDirectory();
    const QFileInfo outDirInfo(m_wizard->outputDirectory());

    kleo_assert(!useOutDir || outDirInfo.isDir());

    const QDir outDir(outDirInfo.absoluteFilePath());
    kleo_assert(!useOutDir || outDir.exists());

    std::vector<std::shared_ptr<Task>> tasks;
    for (int i = 0, end = fileNames.size(); i != end; ++i)
        try {
            qWarning() << "A" << fileNames[i];
            const QDir fileDir = QFileInfo(fileNames[i]).absoluteDir();
            kleo_assert(fileDir.exists());
            tasks.push_back(
                taskFromOperationWidget(m_wizard->operationWidget(static_cast<unsigned int>(i)), fileNames[i], useOutDir ? outDir : fileDir, overwritePolicy));
        } catch (const GpgME::Exception &e) {
            tasks.push_back(Task::makeErrorTask(e.error(), QString::fromLocal8Bit(e.what()), fileNames[i]));
        }

    return tasks;
}

void DecryptVerifyFilesController::setFiles(const QStringList &files)
{
    d->m_passedFiles = files;
}

void DecryptVerifyFilesController::Private::ensureWizardVisible()
{
    ensureWizardCreated();
    q->bringToForeground(m_wizard);
}

DecryptVerifyFilesController::DecryptVerifyFilesController(QObject *parent)
    : Controller(parent)
    , d(new Private(this))
{
}

DecryptVerifyFilesController::DecryptVerifyFilesController(const std::shared_ptr<const ExecutionContext> &ctx, QObject *parent)
    : Controller(ctx, parent)
    , d(new Private(this))
{
}

DecryptVerifyFilesController::~DecryptVerifyFilesController()
{
    qCDebug(KLEOPATRA_LOG);
}

void DecryptVerifyFilesController::start()
{
    d->prepareWizardFromPassedFiles();
    d->ensureWizardVisible();
}

void DecryptVerifyFilesController::setOperation(DecryptVerifyOperation op)
{
    d->m_operation = op;
}

DecryptVerifyOperation DecryptVerifyFilesController::operation() const
{
    return d->m_operation;
}

void DecryptVerifyFilesController::Private::cancelAllTasks()
{
    // we just kill all runnable tasks - this will not result in
    // signal emissions.
    m_runnableTasks.clear();

    // a cancel() will result in a call to
    if (m_runningTask) {
        m_runningTask->cancel();
    }
}

void DecryptVerifyFilesController::cancel()
{
    qCDebug(KLEOPATRA_LOG) << this << __func__;
    try {
        d->m_errorDetected = true;
        if (d->m_wizard) {
            d->m_wizard->close();
        }
        d->cancelAllTasks();
    } catch (const std::exception &e) {
        qCDebug(KLEOPATRA_LOG) << "Caught exception: " << e.what();
    }
}

#include "moc_decryptverifyfilescontroller.cpp"
