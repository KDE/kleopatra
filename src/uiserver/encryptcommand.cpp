/* -*- mode: c++; c-basic-offset:4 -*-
    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2007 Klarälvdalens Datakonsult AB

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include <config-kleopatra.h>

#include "encryptcommand.h"

#include <crypto/newsignencryptemailcontroller.h>

#include <utils/input.h>
#include <utils/kleo_assert.h>
#include <utils/output.h>

#include <Libkleo/KleoException>

#include <KLocalizedString>

#include <QTimer>

using namespace Kleo;
using namespace Kleo::Crypto;

class EncryptCommand::Private : public QObject
{
    Q_OBJECT
private:
    friend class ::Kleo::EncryptCommand;
    EncryptCommand *const q;

public:
    explicit Private(EncryptCommand *qq)
        : q(qq)
        , controller()
    {
    }

private:
    void checkForErrors() const;
    void connectController();

private Q_SLOTS:
    void slotDone();
    void slotError(int, const QString &);
    void slotRecipientsResolved();

private:
    std::shared_ptr<NewSignEncryptEMailController> controller;
};

EncryptCommand::EncryptCommand()
    : AssuanCommandMixin<EncryptCommand>()
    , d(new Private(this))
{
}

EncryptCommand::~EncryptCommand()
{
}

void EncryptCommand::Private::checkForErrors() const
{
    if (q->numFiles())
        throw Exception(makeError(GPG_ERR_CONFLICT), i18n("ENCRYPT is an email mode command, connection seems to be in filemanager mode"));

    if (!q->senders().empty() && !q->informativeSenders())
        throw Exception(makeError(GPG_ERR_CONFLICT), i18n("SENDER may not be given prior to ENCRYPT, except with --info"));

    if (q->inputs().empty())
        throw Exception(makeError(GPG_ERR_ASS_NO_INPUT), i18n("At least one INPUT must be present"));

    if (q->outputs().empty())
        throw Exception(makeError(GPG_ERR_ASS_NO_OUTPUT), i18n("At least one OUTPUT must be present"));

    if (q->outputs().size() != q->inputs().size())
        throw Exception(makeError(GPG_ERR_CONFLICT), i18n("INPUT/OUTPUT count mismatch"));

    if (!q->messages().empty())
        throw Exception(makeError(GPG_ERR_INV_VALUE), i18n("MESSAGE command is not allowed before ENCRYPT"));

    const auto m = q->mementoContent<std::shared_ptr<NewSignEncryptEMailController>>(NewSignEncryptEMailController::mementoName());
    kleo_assert(m);

    if (m && m->isEncrypting()) {
        if (m->protocol() != q->checkProtocol(EMail))
            throw Exception(makeError(GPG_ERR_CONFLICT), i18n("Protocol given conflicts with protocol determined by PREP_ENCRYPT"));

        if (!q->recipients().empty())
            throw Exception(makeError(GPG_ERR_CONFLICT), i18n("New recipients added after PREP_ENCRYPT command"));
        if (!q->senders().empty())
            throw Exception(makeError(GPG_ERR_CONFLICT), i18n("New senders added after PREP_ENCRYPT command"));

    } else {
        if (q->recipients().empty() || q->informativeRecipients())
            throw Exception(makeError(GPG_ERR_MISSING_VALUE), i18n("No recipients given, or only with --info"));
    }
}

void EncryptCommand::Private::connectController()
{
    auto ptr = controller.get();
    connect(ptr, &NewSignEncryptEMailController::certificatesResolved, this, &EncryptCommand::Private::slotRecipientsResolved);
    connect(ptr, &Controller::done, this, &EncryptCommand::Private::slotDone);
    connect(ptr, &Controller::error, this, &EncryptCommand::Private::slotError);
}

int EncryptCommand::doStart()
{
    d->checkForErrors();

    const auto seec = mementoContent<std::shared_ptr<NewSignEncryptEMailController>>(NewSignEncryptEMailController::mementoName());

    if (seec && seec->isEncrypting()) {
        // reuse the controller from a previous PREP_ENCRYPT, if available:
        d->controller = seec;
        d->connectController();
        removeMemento(NewSignEncryptEMailController::mementoName());
        d->controller->setExecutionContext(shared_from_this());
        if (seec->areCertificatesResolved()) {
            QTimer::singleShot(0, d.get(), &Private::slotRecipientsResolved);
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

        d->controller->setEncrypting(true);
        d->controller->setSigning(false);
        d->controller->setProtocol(checkProtocol(EMail));
        d->connectController();
        d->controller->startResolveCertificates(recipients(), senders());
    }

    return 0;
}

void EncryptCommand::Private::slotRecipientsResolved()
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

        cont->startEncryption(q->inputs(), q->outputs());

        return;

    } catch (const Exception &e) {
        q->done(e.error(), e.message());
    } catch (const std::exception &e) {
        q->done(makeError(GPG_ERR_UNEXPECTED),
                i18n("Caught unexpected exception in EncryptCommand::Private::slotRecipientsResolved: %1", QString::fromLocal8Bit(e.what())));
    } catch (...) {
        q->done(makeError(GPG_ERR_UNEXPECTED), i18n("Caught unknown exception in EncryptCommand::Private::slotRecipientsResolved"));
    }
    cont->cancel();
}

void EncryptCommand::Private::slotDone()
{
    q->done();
}

void EncryptCommand::Private::slotError(int err, const QString &details)
{
    q->done(err, details);
}

void EncryptCommand::doCanceled()
{
    if (d->controller) {
        d->controller->cancel();
    }
}

#include "encryptcommand.moc"
