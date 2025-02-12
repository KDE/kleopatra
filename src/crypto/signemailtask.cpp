/*
    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2007 Klarälvdalens Datakonsult AB

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include <config-kleopatra.h>

#include "signemailtask.h"

#include <utils/input.h>
#include <utils/kleo_assert.h>
#include <utils/output.h>

#include <Libkleo/AuditLogEntry>
#include <Libkleo/Formatting>
#include <Libkleo/Stl_Util>

#include <QGpgME/Protocol>
#include <QGpgME/SignJob>

#include <gpgme++/key.h>
#include <gpgme++/signingresult.h>

#include <KLocalizedString>

#include <QPointer>

#include <algorithm>
#include <functional>

using namespace Kleo;
using namespace Kleo::Crypto;
using namespace GpgME;

namespace
{

class SignEMailResult : public Task::Result
{
    const SigningResult m_result;
    const AuditLogEntry m_auditLog;

public:
    explicit SignEMailResult(const SigningResult &r, const AuditLogEntry &auditLog)
        : Task::Result()
        , m_result(r)
        , m_auditLog(auditLog)
    {
    }

    QString overview() const override;
    QString details() const override;
    GpgME::Error error() const override;
    QString errorString() const override;
    AuditLogEntry auditLog() const override;
};

QString makeResultString(const SigningResult &res)
{
    const Error err = res.error();

    if (err.isCanceled()) {
        return i18n("Signing canceled.");
    }

    if (err) {
        return i18n("Signing failed: %1", Formatting::errorAsString(err).toHtmlEscaped());
    }

    return i18n("Signing succeeded.");
}
}

class SignEMailTask::Private
{
    friend class ::Kleo::Crypto::SignEMailTask;
    SignEMailTask *const q;

public:
    explicit Private(SignEMailTask *qq);

private:
    std::unique_ptr<QGpgME::SignJob> createJob(GpgME::Protocol proto);

private:
    void slotResult(const SigningResult &);

private:
    std::shared_ptr<Input> input;
    std::shared_ptr<Output> output;
    std::vector<Key> signers;
    bool detached;
    bool clearsign;

    QString micAlg;

    QPointer<QGpgME::SignJob> job;
};

SignEMailTask::Private::Private(SignEMailTask *qq)
    : q(qq)
    , input()
    , output()
    , signers()
    , detached(false)
    , clearsign(false)
    , micAlg()
    , job(nullptr)
{
}

SignEMailTask::SignEMailTask(QObject *p)
    : Task(p)
    , d(new Private(this))
{
}

SignEMailTask::~SignEMailTask()
{
}

void SignEMailTask::setInput(const std::shared_ptr<Input> &input)
{
    kleo_assert(!d->job);
    kleo_assert(input);
    d->input = input;
}

void SignEMailTask::setOutput(const std::shared_ptr<Output> &output)
{
    kleo_assert(!d->job);
    kleo_assert(output);
    d->output = output;
}

void SignEMailTask::setSigners(const std::vector<Key> &signers)
{
    kleo_assert(!d->job);
    kleo_assert(!signers.empty());
    kleo_assert(std::none_of(signers.cbegin(), signers.cend(), std::mem_fn(&Key::isNull)));
    d->signers = signers;
}

void SignEMailTask::setDetachedSignature(bool detached)
{
    kleo_assert(!d->job);
    d->detached = detached;
    d->clearsign = false;
}

void SignEMailTask::setClearsign(bool clear)
{
    kleo_assert(!d->job);
    d->clearsign = clear;
    d->detached = false;
}

Protocol SignEMailTask::protocol() const
{
    kleo_assert(!d->signers.empty());
    return d->signers.front().protocol();
}

QString SignEMailTask::label() const
{
    return d->input ? d->input->label() : QString();
}

unsigned long long SignEMailTask::inputSize() const
{
    return d->input ? d->input->size() : 0;
}

void SignEMailTask::doStart()
{
    kleo_assert(!d->job);
    kleo_assert(d->input);
    kleo_assert(d->output);
    kleo_assert(!d->signers.empty());

    d->micAlg.clear();

    std::unique_ptr<QGpgME::SignJob> job = d->createJob(protocol());
    kleo_assert(job.get());

    job->start(d->signers,
               d->input->ioDevice(),
               d->output->ioDevice(),
               d->clearsign      ? GpgME::Clearsigned
                   : d->detached ? GpgME::Detached
                                 : GpgME::NormalSignatureMode);

    d->job = job.release();
}

void SignEMailTask::cancel()
{
    if (d->job) {
        d->job->slotCancel();
    }
}

std::unique_ptr<QGpgME::SignJob> SignEMailTask::Private::createJob(GpgME::Protocol proto)
{
    const QGpgME::Protocol *const backend = (proto == GpgME::OpenPGP) ? QGpgME::openpgp() : QGpgME::smime();
    kleo_assert(backend);
    bool shouldArmor = (proto == OpenPGP || q->asciiArmor()) && !output->binaryOpt();
    std::unique_ptr<QGpgME::SignJob> signJob(backend->signJob(/*armor=*/shouldArmor, /*textmode=*/false));
    kleo_assert(signJob.get());
    if (proto == CMS && !q->asciiArmor() && !output->binaryOpt()) {
        signJob->setOutputIsBase64Encoded(true);
    }
    connect(signJob.get(), &QGpgME::Job::jobProgress, q, &SignEMailTask::setProgress);
    connect(signJob.get(), SIGNAL(result(GpgME::SigningResult, QByteArray)), q, SLOT(slotResult(GpgME::SigningResult)));
    return signJob;
}

static QString collect_micalgs(const GpgME::SigningResult &result, GpgME::Protocol proto)
{
    const std::vector<GpgME::CreatedSignature> css = result.createdSignatures();
    QStringList micalgs;
    std::transform(css.begin(), css.end(), std::back_inserter(micalgs), [](const GpgME::CreatedSignature &sig) {
        return QString::fromLatin1(sig.hashAlgorithmAsString()).toLower();
    });
    if (proto == GpgME::OpenPGP)
        for (QStringList::iterator it = micalgs.begin(), end = micalgs.end(); it != end; ++it) {
            it->prepend(QLatin1StringView("pgp-"));
        }
    micalgs.sort();
    micalgs.erase(std::unique(micalgs.begin(), micalgs.end()), micalgs.end());
    return micalgs.join(QLatin1Char(','));
}

void SignEMailTask::Private::slotResult(const SigningResult &result)
{
    const auto *const job = qobject_cast<const QGpgME::Job *>(q->sender());
    if (result.error().code()) {
        output->cancel();
    } else {
        output->finalize();
        micAlg = collect_micalgs(result, q->protocol());
    }
    q->emitResult(std::shared_ptr<Result>(new SignEMailResult(result, AuditLogEntry::fromJob(job))));
}

QString SignEMailTask::micAlg() const
{
    return d->micAlg;
}

QString SignEMailResult::overview() const
{
    return makeOverview(makeResultString(m_result));
}

QString SignEMailResult::details() const
{
    return QString();
}

GpgME::Error SignEMailResult::error() const
{
    return m_result.error();
}

QString SignEMailResult::errorString() const
{
    return hasError() ? makeResultString(m_result) : QString();
}

AuditLogEntry SignEMailResult::auditLog() const
{
    return m_auditLog;
}

#include "moc_signemailtask.cpp"
