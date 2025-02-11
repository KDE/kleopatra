/* -*- mode: c++; c-basic-offset:4 -*-
    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2008 Klarälvdalens Datakonsult AB

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include <config-kleopatra.h>

#include "decryptverifyemailcontroller.h"
#include "kleopatra_debug.h"

#include "emailoperationspreferences.h"

#include <crypto/decryptverifytask.h>
#include <crypto/gui/newresultpage.h>
#include <crypto/taskcollection.h>

#include <Libkleo/GnuPG>
#include <utils/input.h>
#include <utils/kleo_assert.h>
#include <utils/output.h>

#include <QGpgME/Protocol>

#include <Libkleo/Classify>
#include <Libkleo/Formatting>

#include <KMime/Types>

#include <KLocalizedString>

#include <QPoint>
#include <QPointer>
#include <QTimer>

using namespace GpgME;
using namespace Kleo;
using namespace Kleo::Crypto;
using namespace Kleo::Crypto::Gui;
using namespace KMime::Types;

namespace
{

class DecryptVerifyEMailWizard : public QWizard
{
    Q_OBJECT
public:
    explicit DecryptVerifyEMailWizard(QWidget *parent = nullptr, Qt::WindowFlags f = {})
        : QWizard(parent, f)
        , m_resultPage(this)
    {
        Q_SET_OBJECT_NAME(m_resultPage);

        m_resultPage.setSubTitle(i18n("Status and progress of the crypto operations is shown here."));

        addPage(&m_resultPage);
    }

    void addTaskCollection(const std::shared_ptr<TaskCollection> &coll)
    {
        m_resultPage.addTaskCollection(coll);
    }

public Q_SLOTS:
    void accept() override
    {
        EMailOperationsPreferences prefs;
        prefs.setDecryptVerifyPopupGeometry(geometry());
        prefs.save();
        QWizard::accept();
    }

private:
    NewResultPage m_resultPage;
};

}

class DecryptVerifyEMailController::Private
{
    DecryptVerifyEMailController *const q;

public:
    explicit Private(DecryptVerifyEMailController *qq, Task::DataSource dataSource);

    void slotWizardCanceled();
    void schedule();

    std::vector<std::shared_ptr<AbstractDecryptVerifyTask>> buildTasks();

    static DecryptVerifyEMailWizard *findOrCreateWizard(unsigned int id);

    void ensureWizardCreated();
    void ensureWizardVisible();
    void reportError(int err, const QString &details)
    {
        q->setLastError(err, details);
        q->emitDoneOrError();
    }

    void cancelAllTasks();

    std::vector<std::shared_ptr<Input>> m_inputs, m_signedDatas;
    std::vector<std::shared_ptr<Output>> m_outputs;

    unsigned int m_sessionId;
    QPointer<DecryptVerifyEMailWizard> m_wizard;
    std::vector<std::shared_ptr<const DecryptVerifyResult>> m_results;
    std::vector<std::shared_ptr<AbstractDecryptVerifyTask>> m_runnableTasks, m_completedTasks;
    std::shared_ptr<AbstractDecryptVerifyTask> m_runningTask;
    bool m_silent;
    bool m_operationCompleted;
    DecryptVerifyOperation m_operation;
    Protocol m_protocol;
    VerificationMode m_verificationMode;
    std::vector<KMime::Types::Mailbox> m_informativeSenders;
    Task::DataSource m_dataSource;
};

DecryptVerifyEMailController::Private::Private(DecryptVerifyEMailController *qq, Task::DataSource dataSource)
    : q(qq)
    , m_sessionId(0)
    , m_silent(false)
    , m_operationCompleted(false)
    , m_operation(DecryptVerify)
    , m_protocol(UnknownProtocol)
    , m_verificationMode(Detached)
    , m_dataSource(dataSource)
{
    qRegisterMetaType<VerificationResult>();
}

void DecryptVerifyEMailController::Private::slotWizardCanceled()
{
    qCDebug(KLEOPATRA_LOG);
    if (!m_operationCompleted) {
        reportError(gpg_error(GPG_ERR_CANCELED), i18n("User canceled"));
    }
}

void DecryptVerifyEMailController::doTaskDone(const Task *task, const std::shared_ptr<const Task::Result> &result)
{
    Q_ASSERT(task);

    // We could just delete the tasks here, but we can't use
    // Qt::QueuedConnection here (we need sender()) and other slots
    // might not yet have executed. Therefore, we push completed tasks
    // into a burial container

    if (task == d->m_runningTask.get()) {
        d->m_completedTasks.push_back(d->m_runningTask);
        const std::shared_ptr<const DecryptVerifyResult> &dvr = std::dynamic_pointer_cast<const DecryptVerifyResult>(result);
        Q_ASSERT(dvr);
        d->m_results.push_back(dvr);
        d->m_runningTask.reset();
    }

    QTimer::singleShot(0, this, SLOT(schedule()));
}

void DecryptVerifyEMailController::Private::schedule()
{
    if (!m_runningTask && !m_runnableTasks.empty()) {
        const std::shared_ptr<AbstractDecryptVerifyTask> t = m_runnableTasks.back();
        m_runnableTasks.pop_back();
        t->start();
        m_runningTask = t;
    }
    if (!m_runningTask) {
        kleo_assert(m_runnableTasks.empty());
        for (const std::shared_ptr<const DecryptVerifyResult> &i : std::as_const(m_results)) {
            Q_EMIT q->verificationResult(i->verificationResult());
        }
        // if there is a popup, wait for either the client cancel or the user closing the popup.
        // Otherwise (silent case), finish immediately
        m_operationCompleted = true;
        q->emitDoneOrError();
    }
}

void DecryptVerifyEMailController::Private::ensureWizardCreated()
{
    if (m_wizard) {
        return;
    }

    DecryptVerifyEMailWizard *w = findOrCreateWizard(m_sessionId);
    connect(w, SIGNAL(destroyed()), q, SLOT(slotWizardCanceled()), Qt::QueuedConnection);
    m_wizard = w;
}

namespace
{
template<typename C>
void collectGarbage(C &c)
{
    auto it = c.begin();
    while (it != c.end() /*sic!*/)
        if (it->second) {
            ++it;
        } else {
            c.erase(it++ /*sic!*/);
        }
}
}

// static
DecryptVerifyEMailWizard *DecryptVerifyEMailController::Private::findOrCreateWizard(unsigned int id)
{
    static std::map<unsigned int, QPointer<DecryptVerifyEMailWizard>> s_wizards;

    collectGarbage(s_wizards);

    qCDebug(KLEOPATRA_LOG) << "id = " << id;

    if (id != 0) {
        const auto it = s_wizards.find(id);

        if (it != s_wizards.end()) {
            Q_ASSERT(it->second && "This should have been garbage-collected");
            return it->second;
        }
    }

    auto w = new DecryptVerifyEMailWizard;
    w->setWindowTitle(i18nc("@title:window", "Decrypt/Verify E-Mail"));
    w->setAttribute(Qt::WA_DeleteOnClose);

    const QRect preferredGeometry = EMailOperationsPreferences().decryptVerifyPopupGeometry();
    if (preferredGeometry.isValid()) {
        w->setGeometry(preferredGeometry);
    }

    s_wizards[id] = w;

    return w;
}

std::vector<std::shared_ptr<AbstractDecryptVerifyTask>> DecryptVerifyEMailController::Private::buildTasks()
{
    const uint numInputs = m_inputs.size();
    const uint numMessages = m_signedDatas.size();
    const uint numOutputs = m_outputs.size();
    const uint numInformativeSenders = m_informativeSenders.size();

    // these are duplicated from DecryptVerifyCommandEMailBase::Private::checkForErrors with slightly modified error codes/messages
    if (!numInputs)
        throw Kleo::Exception(makeGnuPGError(GPG_ERR_CONFLICT), i18n("At least one input needs to be provided"));

    if (numInformativeSenders > 0 && numInformativeSenders != numInputs)
        throw Kleo::Exception(makeGnuPGError(GPG_ERR_CONFLICT), // TODO use better error code if possible
                              i18n("Informative sender/signed data count mismatch"));

    if (numMessages) {
        if (numMessages != numInputs)
            throw Kleo::Exception(makeGnuPGError(GPG_ERR_CONFLICT), // TODO use better error code if possible
                                  i18n("Signature/signed data count mismatch"));
        else if (m_operation != Verify || m_verificationMode != Detached)
            throw Kleo::Exception(makeGnuPGError(GPG_ERR_CONFLICT), i18n("Signed data can only be given for detached signature verification"));
    }

    if (numOutputs) {
        if (numOutputs != numInputs)
            throw Kleo::Exception(makeGnuPGError(GPG_ERR_CONFLICT), // TODO use better error code if possible
                                  i18n("Input/Output count mismatch"));
        else if (numMessages)
            throw Kleo::Exception(makeGnuPGError(GPG_ERR_CONFLICT), i18n("Cannot use output and signed data simultaneously"));
    }

    kleo_assert(m_protocol != UnknownProtocol);

    const QGpgME::Protocol *const backend = (m_protocol == GpgME::OpenPGP) ? QGpgME::openpgp() : QGpgME::smime();
    if (!backend) {
        throw Kleo::Exception(makeGnuPGError(GPG_ERR_UNSUPPORTED_PROTOCOL), i18n("No backend support for %1", Formatting::displayName(m_protocol)));
    }

    if (m_operation != Decrypt && !m_silent) {
        ensureWizardVisible();
    }

    std::vector<std::shared_ptr<AbstractDecryptVerifyTask>> tasks;

    for (unsigned int i = 0; i < numInputs; ++i) {
        std::shared_ptr<AbstractDecryptVerifyTask> task;
        switch (m_operation) {
        case Decrypt: {
            std::shared_ptr<DecryptTask> t(new DecryptTask);
            t->setInput(m_inputs.at(i));
            Q_ASSERT(numOutputs);
            t->setOutput(m_outputs.at(i));
            t->setProtocol(m_protocol);
            task = t;
        } break;
        case Verify: {
            if (m_verificationMode == Detached) {
                std::shared_ptr<VerifyDetachedTask> t(new VerifyDetachedTask);
                t->setInput(m_inputs.at(i));
                t->setSignedData(m_signedDatas.at(i));
                if (numInformativeSenders > 0) {
                    t->setInformativeSender(m_informativeSenders.at(i));
                }
                t->setProtocol(m_protocol);
                task = t;
            } else {
                std::shared_ptr<VerifyOpaqueTask> t(new VerifyOpaqueTask);
                t->setInput(m_inputs.at(i));
                if (numOutputs) {
                    t->setOutput(m_outputs.at(i));
                }
                if (numInformativeSenders > 0) {
                    t->setInformativeSender(m_informativeSenders.at(i));
                }
                t->setProtocol(m_protocol);
                task = t;
            }
        } break;
        case DecryptVerify: {
            std::shared_ptr<DecryptVerifyTask> t(new DecryptVerifyTask);
            t->setInput(m_inputs.at(i));
            Q_ASSERT(numOutputs);
            t->setOutput(m_outputs.at(i));
            t->setDataSource(m_dataSource);
            if (numInformativeSenders > 0) {
                t->setInformativeSender(m_informativeSenders.at(i));
            }
            t->setProtocol(m_protocol);
            task = t;
        }
        }

        Q_ASSERT(task);
        tasks.push_back(task);
    }

    return tasks;
}

void DecryptVerifyEMailController::Private::ensureWizardVisible()
{
    ensureWizardCreated();
    q->bringToForeground(m_wizard);
}

DecryptVerifyEMailController::DecryptVerifyEMailController(QObject *parent, Task::DataSource dataSource)
    : Controller(parent)
    , d(new Private(this, dataSource))
{
}

DecryptVerifyEMailController::DecryptVerifyEMailController(const std::shared_ptr<const ExecutionContext> &ctx, QObject *parent)
    : Controller(ctx, parent)
    , d(new Private(this, Task::Files))
{
}

DecryptVerifyEMailController::~DecryptVerifyEMailController()
{
    qCDebug(KLEOPATRA_LOG);
}

void DecryptVerifyEMailController::start()
{
    d->m_runnableTasks = d->buildTasks();

    const std::shared_ptr<TaskCollection> coll(new TaskCollection);
    std::vector<std::shared_ptr<Task>> tsks;
    for (std::shared_ptr<Task> i : std::as_const(d->m_runnableTasks)) {
        connectTask(i);
        tsks.push_back(i);
    }
    coll->setTasks(tsks);
    d->ensureWizardCreated();
    d->m_wizard->addTaskCollection(coll);

    d->ensureWizardVisible();
    QTimer::singleShot(0, this, SLOT(schedule()));
}

void DecryptVerifyEMailController::setInput(const std::shared_ptr<Input> &input)
{
    d->m_inputs.resize(1, input);
}

void DecryptVerifyEMailController::setInputs(const std::vector<std::shared_ptr<Input>> &inputs)
{
    d->m_inputs = inputs;
}

void DecryptVerifyEMailController::setSignedData(const std::shared_ptr<Input> &data)
{
    d->m_signedDatas.resize(1, data);
}

void DecryptVerifyEMailController::setSignedData(const std::vector<std::shared_ptr<Input>> &data)
{
    d->m_signedDatas = data;
}

void DecryptVerifyEMailController::setOutput(const std::shared_ptr<Output> &output)
{
    d->m_outputs.resize(1, output);
}

void DecryptVerifyEMailController::setOutputs(const std::vector<std::shared_ptr<Output>> &outputs)
{
    d->m_outputs = outputs;
}

void DecryptVerifyEMailController::setInformativeSenders(const std::vector<KMime::Types::Mailbox> &senders)
{
    d->m_informativeSenders = senders;
}

void DecryptVerifyEMailController::setWizardShown(bool shown)
{
    d->m_silent = !shown;
    if (d->m_wizard) {
        d->m_wizard->setVisible(shown);
    }
}

void DecryptVerifyEMailController::setOperation(DecryptVerifyOperation operation)
{
    d->m_operation = operation;
}

void DecryptVerifyEMailController::setVerificationMode(VerificationMode vm)
{
    d->m_verificationMode = vm;
}

void DecryptVerifyEMailController::setProtocol(Protocol prot)
{
    d->m_protocol = prot;
}

void DecryptVerifyEMailController::setSessionId(unsigned int id)
{
    qCDebug(KLEOPATRA_LOG) << "id = " << id;
    d->m_sessionId = id;
}

void DecryptVerifyEMailController::cancel()
{
    qCDebug(KLEOPATRA_LOG);
    try {
        if (d->m_wizard) {
            disconnect(d->m_wizard);
            d->m_wizard->close();
        }
        d->cancelAllTasks();
    } catch (const std::exception &e) {
        qCDebug(KLEOPATRA_LOG) << "Caught exception: " << e.what();
    }
}

void DecryptVerifyEMailController::Private::cancelAllTasks()
{
    // we just kill all runnable tasks - this will not result in
    // signal emissions.
    m_runnableTasks.clear();

    // a cancel() will result in a call to
    if (m_runningTask) {
        m_runningTask->cancel();
    }
}

#include "decryptverifyemailcontroller.moc"
#include "moc_decryptverifyemailcontroller.cpp"
