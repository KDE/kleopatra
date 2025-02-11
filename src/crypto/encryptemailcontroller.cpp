/* -*- mode: c++; c-basic-offset:4 -*-
    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2007 Klarälvdalens Datakonsult AB

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include <config-kleopatra.h>

#include "encryptemailcontroller.h"
#include "encryptemailtask.h"
#include "kleopatra_debug.h"
#include "taskcollection.h"

#include <crypto/gui/encryptemailwizard.h>

#include <utils/input.h>
#include <utils/kleo_assert.h>
#include <utils/output.h>

#include <Libkleo/KleoException>
#include <Libkleo/Stl_Util>

#include <gpgme++/key.h>

#include <KLocalizedString>

#include <QPointer>

using namespace Kleo;
using namespace Kleo::Crypto;
using namespace Kleo::Crypto::Gui;
using namespace GpgME;
using namespace KMime::Types;

class EncryptEMailController::Private
{
    friend class ::Kleo::Crypto::EncryptEMailController;
    EncryptEMailController *const q;

public:
    explicit Private(Mode mode, EncryptEMailController *qq);

private:
    void slotWizardCanceled();

private:
    void ensureWizardCreated();
    void ensureWizardVisible();
    void cancelAllTasks();

    void schedule();
    std::shared_ptr<EncryptEMailTask> takeRunnable(GpgME::Protocol proto);

private:
    const Mode mode;
    std::vector<std::shared_ptr<EncryptEMailTask>> runnable, completed;
    std::shared_ptr<EncryptEMailTask> cms, openpgp;
    QPointer<EncryptEMailWizard> wizard;
};

EncryptEMailController::Private::Private(Mode m, EncryptEMailController *qq)
    : q(qq)
    , mode(m)
    , runnable()
    , cms()
    , openpgp()
    , wizard()
{
}

EncryptEMailController::EncryptEMailController(const std::shared_ptr<ExecutionContext> &xc, Mode mode, QObject *p)
    : Controller(xc, p)
    , d(new Private(mode, this))
{
}

EncryptEMailController::EncryptEMailController(Mode mode, QObject *p)
    : Controller(p)
    , d(new Private(mode, this))
{
}

EncryptEMailController::~EncryptEMailController()
{
    if (d->wizard && !d->wizard->isVisible()) {
        delete d->wizard;
    }
}

EncryptEMailController::Mode EncryptEMailController::mode() const
{
    return d->mode;
}

void EncryptEMailController::setProtocol(Protocol proto)
{
    d->ensureWizardCreated();
    const Protocol protocol = d->wizard->presetProtocol();
    kleo_assert(protocol == UnknownProtocol || protocol == proto);

    d->wizard->setPresetProtocol(proto);
}

Protocol EncryptEMailController::protocol()
{
    d->ensureWizardCreated();
    return d->wizard->selectedProtocol();
}

const char *EncryptEMailController::protocolAsString()
{
    switch (protocol()) {
    case OpenPGP:
        return "OpenPGP";
    case CMS:
        return "CMS";
    default:
        throw Kleo::Exception(gpg_error(GPG_ERR_INTERNAL), i18n("Call to EncryptEMailController::protocolAsString() is ambiguous."));
    }
}

void EncryptEMailController::startResolveRecipients()
{
    d->ensureWizardCreated();
    d->ensureWizardVisible();
}

void EncryptEMailController::Private::slotWizardCanceled()
{
    q->setLastError(gpg_error(GPG_ERR_CANCELED), i18n("User cancel"));
    q->emitDoneOrError();
}

void EncryptEMailController::setInputAndOutput(const std::shared_ptr<Input> &input, const std::shared_ptr<Output> &output)
{
    setInputsAndOutputs(std::vector<std::shared_ptr<Input>>(1, input), std::vector<std::shared_ptr<Output>>(1, output));
}

void EncryptEMailController::setInputsAndOutputs(const std::vector<std::shared_ptr<Input>> &inputs, const std::vector<std::shared_ptr<Output>> &outputs)
{
    kleo_assert(!inputs.empty());
    kleo_assert(outputs.size() == inputs.size());

    std::vector<std::shared_ptr<EncryptEMailTask>> tasks;
    tasks.reserve(inputs.size());

    d->ensureWizardCreated();

    const std::vector<Key> keys = d->wizard->resolvedCertificates();
    kleo_assert(!keys.empty());

    for (unsigned int i = 0, end = inputs.size(); i < end; ++i) {
        const std::shared_ptr<EncryptEMailTask> task(new EncryptEMailTask);
        task->setInput(inputs[i]);
        task->setOutput(outputs[i]);
        if (d->mode == ClipboardMode) {
            task->setAsciiArmor(true);
        }
        task->setRecipients(keys);

        tasks.push_back(task);
    }

    d->runnable.swap(tasks);
}

void EncryptEMailController::start()
{
    std::shared_ptr<TaskCollection> coll(new TaskCollection);
    std::vector<std::shared_ptr<Task>> tmp;
    std::copy(d->runnable.begin(), d->runnable.end(), std::back_inserter(tmp));
    coll->setTasks(tmp);
    d->ensureWizardCreated();
    d->wizard->setTaskCollection(coll);
    for (const std::shared_ptr<Task> &t : std::as_const(tmp)) {
        connectTask(t);
    }
    d->schedule();
}

void EncryptEMailController::Private::schedule()
{
    if (!cms)
        if (const std::shared_ptr<EncryptEMailTask> t = takeRunnable(CMS)) {
            t->start();
            cms = t;
        }

    if (!openpgp)
        if (const std::shared_ptr<EncryptEMailTask> t = takeRunnable(OpenPGP)) {
            t->start();
            openpgp = t;
        }

    if (cms || openpgp) {
        return;
    }
    kleo_assert(runnable.empty());
    q->emitDoneOrError();
}

std::shared_ptr<EncryptEMailTask> EncryptEMailController::Private::takeRunnable(GpgME::Protocol proto)
{
    const auto it = std::find_if(runnable.begin(), runnable.end(), [proto](const std::shared_ptr<Kleo::Crypto::EncryptEMailTask> &task) {
        return task->protocol() == proto;
    });
    if (it == runnable.end()) {
        return std::shared_ptr<EncryptEMailTask>();
    }

    const std::shared_ptr<EncryptEMailTask> result = *it;
    runnable.erase(it);
    return result;
}

void EncryptEMailController::doTaskDone(const Task *task, const std::shared_ptr<const Task::Result> &result)
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

    QMetaObject::invokeMethod(
        this,
        [this]() {
            d->schedule();
        },
        Qt::QueuedConnection);
}

void EncryptEMailController::cancel()
{
    try {
        if (d->wizard) {
            d->wizard->close();
        }
        d->cancelAllTasks();
    } catch (const std::exception &e) {
        qCDebug(KLEOPATRA_LOG) << "Caught exception: " << e.what();
    }
}

void EncryptEMailController::Private::cancelAllTasks()
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

void EncryptEMailController::Private::ensureWizardCreated()
{
    if (wizard) {
        return;
    }

    std::unique_ptr<EncryptEMailWizard> w(new EncryptEMailWizard);
    w->setAttribute(Qt::WA_DeleteOnClose);
    connect(w.get(), &EncryptEMailWizard::recipientsResolved, q, &EncryptEMailController::recipientsResolved, Qt::QueuedConnection);
    connect(
        w.get(),
        &EncryptEMailWizard::canceled,
        q,
        [this]() {
            slotWizardCanceled();
        },
        Qt::QueuedConnection);

    wizard = w.release();
}

void EncryptEMailController::Private::ensureWizardVisible()
{
    ensureWizardCreated();
    q->bringToForeground(wizard);
}

#include "moc_encryptemailcontroller.cpp"
