/*
    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2009, 2010 Klarälvdalens Datakonsult AB

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include <config-kleopatra.h>

#include "encryptemailtask.h"
#include "kleopatra_debug.h"
#include "newsignencryptemailcontroller.h"
#include "recipient.h"
#include "sender.h"
#include "signemailtask.h"
#include "taskcollection.h"

#include <crypto/gui/signencryptemailconflictdialog.h>

#include "utils/input.h"
#include "utils/kleo_assert.h"
#include "utils/output.h"
#include <Libkleo/GnuPG>

#include <Libkleo/Compliance>
#include <Libkleo/KleoException>
#include <Libkleo/Stl_Util>

#include <gpgme++/key.h>

#include <KMime/Types>

#include <KLocalizedString>

#include <KMessageBox>

#include <QPointer>
#include <QTimer>

using namespace Kleo;
using namespace Kleo::Crypto;
using namespace Kleo::Crypto::Gui;
using namespace GpgME;
using namespace KMime::Types;

static std::vector<Sender> mailbox2sender(const std::vector<Mailbox> &mbs)
{
    std::vector<Sender> senders;
    senders.reserve(mbs.size());
    for (const Mailbox &mb : mbs) {
        senders.push_back(Sender(mb));
    }
    return senders;
}

static std::vector<Recipient> mailbox2recipient(const std::vector<Mailbox> &mbs)
{
    std::vector<Recipient> recipients;
    recipients.reserve(mbs.size());
    for (const Mailbox &mb : mbs) {
        recipients.push_back(Recipient(mb));
    }
    return recipients;
}

class NewSignEncryptEMailController::Private
{
    friend class ::Kleo::Crypto::NewSignEncryptEMailController;
    NewSignEncryptEMailController *const q;

public:
    explicit Private(NewSignEncryptEMailController *qq);
    ~Private();

private:
    void slotDialogAccepted();
    void slotDialogRejected();

private:
    void ensureDialogVisible();
    void cancelAllTasks();

    void startSigning();
    void startEncryption();
    void schedule();
    std::shared_ptr<Task> takeRunnable(GpgME::Protocol proto);

private:
    bool sign : 1;
    bool encrypt : 1;
    bool resolvingInProgress : 1;
    bool certificatesResolved : 1;
    bool detached : 1;
    Protocol presetProtocol;
    std::vector<Key> signers, recipients;
    std::vector<std::shared_ptr<Task>> runnable, completed;
    std::shared_ptr<Task> cms, openpgp;
    QPointer<SignEncryptEMailConflictDialog> dialog;
};

NewSignEncryptEMailController::Private::Private(NewSignEncryptEMailController *qq)
    : q(qq)
    , sign(false)
    , encrypt(false)
    , resolvingInProgress(false)
    , certificatesResolved(false)
    , detached(false)
    , presetProtocol(UnknownProtocol)
    , signers()
    , recipients()
    , runnable()
    , cms()
    , openpgp()
    , dialog(new SignEncryptEMailConflictDialog)
{
    connect(dialog, SIGNAL(accepted()), q, SLOT(slotDialogAccepted()));
    connect(dialog, SIGNAL(rejected()), q, SLOT(slotDialogRejected()));
}

NewSignEncryptEMailController::Private::~Private()
{
    delete dialog;
}

NewSignEncryptEMailController::NewSignEncryptEMailController(const std::shared_ptr<ExecutionContext> &xc, QObject *p)
    : Controller(xc, p)
    , d(new Private(this))
{
}

NewSignEncryptEMailController::NewSignEncryptEMailController(QObject *p)
    : Controller(p)
    , d(new Private(this))
{
}

NewSignEncryptEMailController::~NewSignEncryptEMailController()
{
    qCDebug(KLEOPATRA_LOG);
}

void NewSignEncryptEMailController::setSubject(const QString &subject)
{
    d->dialog->setSubject(subject);
}

void NewSignEncryptEMailController::setProtocol(Protocol proto)
{
    d->presetProtocol = proto;
    d->dialog->setPresetProtocol(proto);
}

Protocol NewSignEncryptEMailController::protocol() const
{
    return d->dialog->selectedProtocol();
}

const char *NewSignEncryptEMailController::protocolAsString() const
{
    switch (protocol()) {
    case OpenPGP:
        return "OpenPGP";
    case CMS:
        return "CMS";
    default:
        throw Kleo::Exception(gpg_error(GPG_ERR_INTERNAL), i18n("Call to NewSignEncryptEMailController::protocolAsString() is ambiguous."));
    }
}

void NewSignEncryptEMailController::setSigning(bool sign)
{
    d->sign = sign;
    d->dialog->setSign(sign);
}

bool NewSignEncryptEMailController::isSigning() const
{
    return d->sign;
}

void NewSignEncryptEMailController::setEncrypting(bool encrypt)
{
    d->encrypt = encrypt;
    d->dialog->setEncrypt(encrypt);
}

bool NewSignEncryptEMailController::isEncrypting() const
{
    return d->encrypt;
}

void NewSignEncryptEMailController::setDetachedSignature(bool detached)
{
    d->detached = detached;
}

bool NewSignEncryptEMailController::isResolvingInProgress() const
{
    return d->resolvingInProgress;
}

bool NewSignEncryptEMailController::areCertificatesResolved() const
{
    return d->certificatesResolved;
}

void NewSignEncryptEMailController::startResolveCertificates(const std::vector<Mailbox> &r, const std::vector<Mailbox> &s)
{
    d->certificatesResolved = false;
    d->resolvingInProgress = true;

    const std::vector<Sender> senders = mailbox2sender(s);
    const std::vector<Recipient> recipients = mailbox2recipient(r);

    d->dialog->setQuickMode(false);
    d->dialog->setSenders(senders);
    d->dialog->setRecipients(recipients);
    d->dialog->pickProtocol();
    d->dialog->setConflict(false);

    d->ensureDialogVisible();
}

void NewSignEncryptEMailController::Private::slotDialogAccepted()
{
    resolvingInProgress = false;
    certificatesResolved = true;
    signers = dialog->resolvedSigningKeys();
    recipients = dialog->resolvedEncryptionKeys();
    QMetaObject::invokeMethod(q, "certificatesResolved", Qt::QueuedConnection);
}

void NewSignEncryptEMailController::Private::slotDialogRejected()
{
    resolvingInProgress = false;
    certificatesResolved = false;
    QMetaObject::invokeMethod(q, "error", Qt::QueuedConnection, Q_ARG(int, gpg_error(GPG_ERR_CANCELED)), Q_ARG(QString, i18n("User cancel")));
}

void NewSignEncryptEMailController::startEncryption(const std::vector<std::shared_ptr<Input>> &inputs, const std::vector<std::shared_ptr<Output>> &outputs)
{
    kleo_assert(d->encrypt);
    kleo_assert(!d->resolvingInProgress);

    kleo_assert(!inputs.empty());
    kleo_assert(outputs.size() == inputs.size());

    std::vector<std::shared_ptr<Task>> tasks;
    tasks.reserve(inputs.size());

    kleo_assert(!d->recipients.empty());

    for (unsigned int i = 0, end = inputs.size(); i < end; ++i) {
        const std::shared_ptr<EncryptEMailTask> task(new EncryptEMailTask);

        task->setInput(inputs[i]);
        task->setOutput(outputs[i]);
        task->setRecipients(d->recipients);

        tasks.push_back(task);
    }

    // append to runnable stack
    d->runnable.insert(d->runnable.end(), tasks.begin(), tasks.end());

    d->startEncryption();
}

void NewSignEncryptEMailController::Private::startEncryption()
{
    std::shared_ptr<TaskCollection> coll(new TaskCollection);
    std::vector<std::shared_ptr<Task>> tmp;
    tmp.reserve(runnable.size());
    std::copy(runnable.cbegin(), runnable.cend(), std::back_inserter(tmp));
    coll->setTasks(tmp);
#if 0
#warning use a new result dialog
    // ### use a new result dialog
    dialog->setTaskCollection(coll);
#endif
    for (const std::shared_ptr<Task> &t : std::as_const(tmp)) {
        q->connectTask(t);
    }
    schedule();
}

void NewSignEncryptEMailController::startSigning(const std::vector<std::shared_ptr<Input>> &inputs, const std::vector<std::shared_ptr<Output>> &outputs)
{
    kleo_assert(d->sign);
    kleo_assert(!d->resolvingInProgress);

    kleo_assert(!inputs.empty());
    kleo_assert(!outputs.empty());

    std::vector<std::shared_ptr<Task>> tasks;
    tasks.reserve(inputs.size());

    kleo_assert(!d->signers.empty());
    kleo_assert(std::none_of(d->signers.cbegin(), d->signers.cend(), std::mem_fn(&Key::isNull)));

    for (unsigned int i = 0, end = inputs.size(); i < end; ++i) {
        const std::shared_ptr<SignEMailTask> task(new SignEMailTask);

        task->setInput(inputs[i]);
        task->setOutput(outputs[i]);
        task->setSigners(d->signers);
        task->setDetachedSignature(d->detached);

        tasks.push_back(task);
    }

    // append to runnable stack
    d->runnable.insert(d->runnable.end(), tasks.begin(), tasks.end());

    d->startSigning();
}

void NewSignEncryptEMailController::Private::startSigning()
{
    std::shared_ptr<TaskCollection> coll(new TaskCollection);
    std::vector<std::shared_ptr<Task>> tmp;
    tmp.reserve(runnable.size());
    std::copy(runnable.cbegin(), runnable.cend(), std::back_inserter(tmp));
    coll->setTasks(tmp);
#if 0
#warning use a new result dialog
    // ### use a new result dialog
    dialog->setTaskCollection(coll);
#endif
    for (const std::shared_ptr<Task> &t : std::as_const(tmp)) {
        q->connectTask(t);
    }
    schedule();
}

void NewSignEncryptEMailController::Private::schedule()
{
    if (!cms)
        if (const std::shared_ptr<Task> t = takeRunnable(CMS)) {
            t->start();
            cms = t;
        }

    if (!openpgp)
        if (const std::shared_ptr<Task> t = takeRunnable(OpenPGP)) {
            t->start();
            openpgp = t;
        }

    if (cms || openpgp) {
        return;
    }
    kleo_assert(runnable.empty());
    q->emitDoneOrError();
}

std::shared_ptr<Task> NewSignEncryptEMailController::Private::takeRunnable(GpgME::Protocol proto)
{
    const auto it = std::find_if(runnable.begin(), runnable.end(), [proto](const std::shared_ptr<Task> &task) {
        return task->protocol() == proto;
    });
    if (it == runnable.end()) {
        return std::shared_ptr<Task>();
    }

    const std::shared_ptr<Task> result = *it;
    runnable.erase(it);
    return result;
}

void NewSignEncryptEMailController::doTaskDone(const Task *task, const std::shared_ptr<const Task::Result> &result)
{
    Q_ASSERT(task);

    if (result && result->hasError()) {
        QPointer<QObject> that = this;
        if (result->details().isEmpty())
            KMessageBox::error(nullptr, result->overview(), i18nc("@title:window", "Error"));
        else
            KMessageBox::detailedError(nullptr, result->overview(), result->details(), i18nc("@title:window", "Error"));
        if (!that) {
            return;
        }
    }

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

void NewSignEncryptEMailController::cancel()
{
    try {
        d->dialog->close();
        d->cancelAllTasks();
    } catch (const std::exception &e) {
        qCDebug(KLEOPATRA_LOG) << "Caught exception: " << e.what();
    }
}

void NewSignEncryptEMailController::Private::cancelAllTasks()
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

void NewSignEncryptEMailController::Private::ensureDialogVisible()
{
    q->bringToForeground(dialog, true);
}

#include "moc_newsignencryptemailcontroller.cpp"
