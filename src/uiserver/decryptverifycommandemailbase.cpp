/* -*- mode: c++; c-basic-offset:4 -*-
    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2007 Klarälvdalens Datakonsult AB

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include <config-kleopatra.h>

#include "decryptverifycommandemailbase.h"

#include <crypto/decryptverifyemailcontroller.h>
#include <crypto/decryptverifytask.h>

#include <utils/input.h>
#include <utils/kleo_assert.h>
#include <utils/output.h>

#include <Libkleo/Formatting>
#include <Libkleo/Hex>
#include <Libkleo/KeyCache>
#include <Libkleo/KleoException>

#include <QGpgME/Protocol>

#include <gpgme++/error.h>
#include <gpgme++/key.h>
#include <gpgme++/verificationresult.h>

#include <KLocalizedString>

#include <gpg-error.h>

using namespace Kleo;
using namespace Kleo::Crypto;
using namespace Kleo::Formatting;
using namespace GpgME;

class DecryptVerifyCommandEMailBase::Private : public QObject
{
    Q_OBJECT
    friend class ::Kleo::DecryptVerifyCommandEMailBase;
    DecryptVerifyCommandEMailBase *const q;

public:
    explicit Private(DecryptVerifyCommandEMailBase *qq)
        : QObject()
        , q(qq)
        , controller()
    {
    }

    ~Private() override
    {
    }

    void checkForErrors() const;

public Q_SLOTS:
    void slotProgress(const QString &what, int current, int total);
    void verificationResult(const GpgME::VerificationResult &);
    void slotDone()
    {
        q->done();
    }
    void slotError(int err, const QString &details)
    {
        q->done(err, details);
    }

public:
private:
    std::shared_ptr<DecryptVerifyEMailController> controller;
};

DecryptVerifyCommandEMailBase::DecryptVerifyCommandEMailBase()
    : AssuanCommandMixin<DecryptVerifyCommandEMailBase>()
    , d(new Private(this))
{
}

DecryptVerifyCommandEMailBase::~DecryptVerifyCommandEMailBase()
{
}

int DecryptVerifyCommandEMailBase::doStart()
{
    d->checkForErrors();

    d->controller.reset(new DecryptVerifyEMailController(shared_from_this()));

    const QString st = sessionTitle();
    if (!st.isEmpty()) {
        const std::vector<std::shared_ptr<Input>> allInputs = inputs();
        for (const std::shared_ptr<Input> &i : allInputs) {
            i->setLabel(st);
        }
    }

    d->controller->setSessionId(sessionId());
    d->controller->setOperation(operation());
    d->controller->setVerificationMode(messages().empty() ? Opaque : Detached);
    d->controller->setInputs(inputs());
    d->controller->setSignedData(messages());
    d->controller->setOutputs(outputs());
    d->controller->setWizardShown(!hasOption("silent"));
    d->controller->setProtocol(checkProtocol(mode()));
    if (informativeSenders()) {
        d->controller->setInformativeSenders(senders());
    }
    QObject::connect(d->controller.get(), &Controller::done, d.get(), &Private::slotDone, Qt::QueuedConnection);
    QObject::connect(d->controller.get(), &Controller::error, d.get(), &Private::slotError, Qt::QueuedConnection);
    QObject::connect(d->controller.get(), &DecryptVerifyEMailController::verificationResult, d.get(), &Private::verificationResult, Qt::QueuedConnection);

    d->controller->start();

    return 0;
}

void DecryptVerifyCommandEMailBase::Private::checkForErrors() const
{
    if (!q->senders().empty() && !q->informativeSenders())
        throw Kleo::Exception(q->makeError(GPG_ERR_CONFLICT), i18n("Cannot use non-info SENDER"));

    if (!q->recipients().empty() && !q->informativeRecipients())
        throw Kleo::Exception(q->makeError(GPG_ERR_CONFLICT), i18n("Cannot use non-info RECIPIENT"));

    // ### use informative recipients and senders

    const unsigned int numInputs = q->inputs().size();
    const unsigned int numMessages = q->messages().size();
    const unsigned int numOutputs = q->outputs().size();
    const unsigned int numInformativeSenders = q->informativeSenders() ? q->senders().size() : 0;

    const DecryptVerifyOperation op = q->operation();
    const GpgME::Protocol proto = q->checkProtocol(q->mode());

    const unsigned int numFiles = q->numFiles();

    if (numFiles) {
        throw Kleo::Exception(q->makeError(GPG_ERR_CONFLICT), i18n("FILES present"));
    }

    if (!numInputs)
        throw Kleo::Exception(q->makeError(GPG_ERR_ASS_NO_INPUT), i18n("At least one INPUT needs to be provided"));

    if (numInformativeSenders != 0)
        if (numInformativeSenders != numInputs)
            throw Kleo::Exception(q->makeError(GPG_ERR_ASS_NO_INPUT), // TODO use better error code if possible
                                  i18n("INPUT/SENDER --info count mismatch"));

    if (numMessages) {
        if (numMessages != numInputs)
            throw Kleo::Exception(q->makeError(GPG_ERR_ASS_NO_INPUT), // TODO use better error code if possible
                                  i18n("INPUT/MESSAGE count mismatch"));
        else if (op != Verify)
            throw Kleo::Exception(q->makeError(GPG_ERR_CONFLICT), i18n("MESSAGE can only be given for detached signature verification"));
    }

    if (numOutputs) {
        if (numOutputs != numInputs)
            throw Kleo::Exception(q->makeError(GPG_ERR_ASS_NO_OUTPUT), // TODO use better error code if possible
                                  i18n("INPUT/OUTPUT count mismatch"));
        else if (numMessages)
            throw Kleo::Exception(q->makeError(GPG_ERR_CONFLICT), i18n("Cannot use OUTPUT and MESSAGE simultaneously"));
    }

    kleo_assert(proto != UnknownProtocol);

    const auto backend = (proto == GpgME::OpenPGP) ? QGpgME::openpgp() : QGpgME::smime();
    if (!backend)
        throw Kleo::Exception(q->makeError(GPG_ERR_UNSUPPORTED_PROTOCOL),
                              proto == OpenPGP   ? i18n("No backend support for OpenPGP")
                                  : proto == CMS ? i18n("No backend support for S/MIME")
                                                 : QString());
}

void DecryptVerifyCommandEMailBase::doCanceled()
{
    if (d->controller) {
        d->controller->cancel();
    }
}

void DecryptVerifyCommandEMailBase::Private::slotProgress(const QString &what, int current, int total)
{
    Q_UNUSED(what)
    Q_UNUSED(current)
    Q_UNUSED(total)
    // ### FIXME report progress, via sendStatus()
}

void DecryptVerifyCommandEMailBase::Private::verificationResult(const VerificationResult &vResult)
{
    try {
        const std::vector<Signature> sigs = vResult.signatures();
        for (const Signature &sig : sigs) {
            const QString s = signatureToString(sig, sig.key(true, true));
            const char *color = summaryToString(sig.summary());
            q->sendStatusEncoded("SIGSTATUS", color + (' ' + hexencode(s.toUtf8().constData())));
        }
    } catch (...) {
    }
}

#include "decryptverifycommandemailbase.moc"
