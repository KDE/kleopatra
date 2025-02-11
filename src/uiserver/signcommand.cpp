/* -*- mode: c++; c-basic-offset:4 -*-
    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2010 Klarälvdalens Datakonsult AB

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include <config-kleopatra.h>

#include "signcommand.h"

#include <crypto/newsignencryptemailcontroller.h>

#include <utils/input.h>
#include <utils/kleo_assert.h>
#include <utils/output.h>

#include <Libkleo/KleoException>

#include <KLocalizedString>

#include <QTimer>

using namespace Kleo;
using namespace Kleo::Crypto;

class SignCommand::Private : public QObject
{
    Q_OBJECT
private:
    friend class ::Kleo::SignCommand;
    SignCommand *const q;

public:
    explicit Private(SignCommand *qq)
        : q(qq)
        , controller()
    {
    }

private:
    void checkForErrors() const;
    void connectController();

private Q_SLOTS:
    void slotSignersResolved();
    void slotMicAlgDetermined(const QString &);
    void slotDone();
    void slotError(int, const QString &);

private:
    std::shared_ptr<NewSignEncryptEMailController> controller;
};

SignCommand::SignCommand()
    : AssuanCommandMixin<SignCommand>()
    , d(new Private(this))
{
}

SignCommand::~SignCommand()
{
}

void SignCommand::Private::checkForErrors() const
{
    if (q->numFiles())
        throw Exception(makeError(GPG_ERR_CONFLICT), i18n("SIGN is an email mode command, connection seems to be in filemanager mode"));

    if (!q->recipients().empty() && !q->informativeRecipients())
        throw Exception(makeError(GPG_ERR_CONFLICT), i18n("RECIPIENT may not be given prior to SIGN, except with --info"));

    if (q->inputs().empty())
        throw Exception(makeError(GPG_ERR_ASS_NO_INPUT), i18n("At least one INPUT must be present"));

    if (q->outputs().size() != q->inputs().size())
        throw Exception(makeError(GPG_ERR_ASS_NO_INPUT), i18n("INPUT/OUTPUT count mismatch"));

    if (!q->messages().empty())
        throw Exception(makeError(GPG_ERR_INV_VALUE), i18n("MESSAGE command is not allowed before SIGN"));

    const auto m = q->mementoContent<std::shared_ptr<NewSignEncryptEMailController>>(NewSignEncryptEMailController::mementoName());

    if (m && m->isSigning()) {
        if (m->protocol() != q->checkProtocol(EMail))
            throw Exception(makeError(GPG_ERR_CONFLICT), i18n("Protocol given conflicts with protocol determined by PREP_ENCRYPT in this session"));

        // ### check that any SENDER here is the same as the one for PREP_ENCRYPT

        // ### ditto RECIPIENT

    } else {
        // ### support the stupid "default signer" semantics of GpgOL
        // ### where SENDER is missing
        if (false)
            if (q->senders().empty() || q->informativeSenders())
                throw Exception(makeError(GPG_ERR_MISSING_VALUE), i18n("No senders given, or only with --info"));
    }
}

void SignCommand::Private::connectController()
{
    NewSignEncryptEMailController *ptr = controller.get();
    QObject::connect(ptr, &NewSignEncryptEMailController::certificatesResolved, this, &SignCommand::Private::slotSignersResolved);
    QObject::connect(ptr, &NewSignEncryptEMailController::reportMicAlg, this, &SignCommand::Private::slotMicAlgDetermined);
    QObject::connect(ptr, &Controller::done, this, &SignCommand::Private::slotDone);
    QObject::connect(ptr, &Controller::error, this, &SignCommand::Private::slotError);
}

int SignCommand::doStart()
{
    d->checkForErrors();

    const auto seec = mementoContent<std::shared_ptr<NewSignEncryptEMailController>>(NewSignEncryptEMailController::mementoName());

    if (seec && seec->isSigning()) {
        // reuse the controller from a previous PREP_ENCRYPT --expect-sign, if available:
        d->controller = seec;
        d->connectController();
        if (!seec->isEncrypting()) {
            removeMemento(NewSignEncryptEMailController::mementoName());
        }
        seec->setExecutionContext(shared_from_this());
        if (seec->areCertificatesResolved()) {
            QTimer::singleShot(0, d.get(), &Private::slotSignersResolved);
        } else {
            kleo_assert(seec->isResolvingInProgress());
        }
    } else {
        // use a new controller
        d->controller.reset(new NewSignEncryptEMailController(shared_from_this()));

        const QString session = sessionTitle();
        if (!session.isEmpty()) {
            d->controller->setSubject(session);
        }

        d->controller->setSigning(true);
        d->controller->setEncrypting(false);
        d->controller->setProtocol(checkProtocol(EMail, AssuanCommand::AllowProtocolMissing));
        d->connectController();
        d->controller->startResolveCertificates(recipients(), senders());
    }

    return 0;
}

void SignCommand::Private::slotSignersResolved()
{
    // hold local std::shared_ptr to member as q->done() deletes *this
    const std::shared_ptr<NewSignEncryptEMailController> cont(controller);

    try {
        const QString sessionTitle = q->sessionTitle();
        if (!sessionTitle.isEmpty()) {
            const std::vector<std::shared_ptr<Input>> allInputs = q->inputs();
            for (const std::shared_ptr<Input> &i : allInputs) {
                i->setLabel(sessionTitle);
            }
        }

        cont->setDetachedSignature(q->hasOption("detached"));
        cont->startSigning(q->inputs(), q->outputs());

        return;

    } catch (const Exception &e) {
        q->done(e.error(), e.message());
    } catch (const std::exception &e) {
        q->done(makeError(GPG_ERR_UNEXPECTED),
                i18n("Caught unexpected exception in SignCommand::Private::slotRecipientsResolved: %1", QString::fromLocal8Bit(e.what())));
    } catch (...) {
        q->done(makeError(GPG_ERR_UNEXPECTED), i18n("Caught unknown exception in SignCommand::Private::slotRecipientsResolved"));
    }
    cont->cancel();
}

void SignCommand::Private::slotMicAlgDetermined(const QString &micalg)
{
    // hold local std::shared_ptr to member as q->done() deletes *this
    const std::shared_ptr<NewSignEncryptEMailController> cont(controller);

    try {
        q->sendStatus("MICALG", micalg);
        return;

    } catch (const Exception &e) {
        q->done(e.error(), e.message());
    } catch (const std::exception &e) {
        q->done(makeError(GPG_ERR_UNEXPECTED),
                i18n("Caught unexpected exception in SignCommand::Private::slotMicAlgDetermined: %1", QString::fromLocal8Bit(e.what())));
    } catch (...) {
        q->done(makeError(GPG_ERR_UNEXPECTED), i18n("Caught unknown exception in SignCommand::Private::slotMicAlgDetermined"));
    }
    cont->cancel();
}

void SignCommand::Private::slotDone()
{
    q->done();
}

void SignCommand::Private::slotError(int err, const QString &details)
{
    q->done(err, details);
}

void SignCommand::doCanceled()
{
    if (d->controller) {
        d->controller->cancel();
    }
}

#include "signcommand.moc"
