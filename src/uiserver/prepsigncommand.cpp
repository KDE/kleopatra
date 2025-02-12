/*
    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2007 Klarälvdalens Datakonsult AB

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include <config-kleopatra.h>

#include "prepsigncommand.h"

#include <crypto/newsignencryptemailcontroller.h>

#include <utils/kleo_assert.h>

#include <Libkleo/KleoException>

#include <KLocalizedString>

#include <QPointer>
#include <QTimer>

using namespace Kleo;
using namespace Kleo::Crypto;

class PrepSignCommand::Private : public QObject
{
    Q_OBJECT
private:
    friend class ::Kleo::PrepSignCommand;
    PrepSignCommand *const q;

public:
    explicit Private(PrepSignCommand *qq)
        : q(qq)
        , controller()
    {
    }

private:
    void checkForErrors() const;
    void connectController();

public Q_SLOTS:
    void slotSignersResolved();
    void slotError(int, const QString &);

private:
    std::shared_ptr<NewSignEncryptEMailController> controller;
};

PrepSignCommand::PrepSignCommand()
    : AssuanCommandMixin<PrepSignCommand>()
    , d(new Private(this))
{
}

PrepSignCommand::~PrepSignCommand()
{
}

void PrepSignCommand::Private::checkForErrors() const
{
    if (!q->inputs().empty() || !q->outputs().empty() || !q->messages().empty())
        throw Exception(makeError(GPG_ERR_CONFLICT), i18n("INPUT/OUTPUT/MESSAGE may only be given after PREP_SIGN"));

    if (q->numFiles())
        throw Exception(makeError(GPG_ERR_CONFLICT), i18n("PREP_SIGN is an email mode command, connection seems to be in filemanager mode"));

    if (q->senders().empty())
        throw Exception(makeError(GPG_ERR_CONFLICT), i18n("No SENDER given"));

    const auto m = q->mementoContent<std::shared_ptr<NewSignEncryptEMailController>>(NewSignEncryptEMailController::mementoName());

    if (m && m->isSigning()) {
        if (q->hasOption("protocol"))
            if (m->protocol() != q->checkProtocol(EMail))
                throw Exception(makeError(GPG_ERR_CONFLICT), i18n("Protocol given conflicts with protocol determined by PREP_ENCRYPT in this session"));

        // ### check that any SENDER here is the same as the one for PREP_ENCRYPT

        // ### ditto RECIPIENT
    }
}

void PrepSignCommand::Private::connectController()
{
    auto ptr = controller.get();
    connect(ptr, &NewSignEncryptEMailController::certificatesResolved, this, &PrepSignCommand::Private::slotSignersResolved);
    connect(ptr, &Controller::error, this, &PrepSignCommand::Private::slotError);
}

int PrepSignCommand::doStart()
{
    d->checkForErrors();

    const auto seec = mementoContent<std::shared_ptr<NewSignEncryptEMailController>>(NewSignEncryptEMailController::mementoName());

    if (seec && seec->isSigning()) {
        // reuse the controller from a previous PREP_ENCRYPT --expect-sign, if available:
        d->controller = seec;
        d->connectController();
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

        if (hasOption("protocol"))
        // --protocol is optional for PREP_SIGN
        {
            d->controller->setProtocol(checkProtocol(EMail));
        }

        d->controller->setEncrypting(false);
        d->controller->setSigning(true);
        d->connectController();
        d->controller->startResolveCertificates(recipients(), senders());
    }

    return 0;
}

void PrepSignCommand::Private::slotSignersResolved()
{
    // hold local std::shared_ptr to member as q->done() deletes *this
    const std::shared_ptr<NewSignEncryptEMailController> cont = controller;
    QPointer<Private> that(this);

    try {
        q->sendStatus("PROTOCOL", QLatin1StringView(controller->protocolAsString()));
        q->registerMemento(NewSignEncryptEMailController::mementoName(), make_typed_memento(controller));
        q->done();
        return;

    } catch (const Exception &e) {
        q->done(e.error(), e.message());
    } catch (const std::exception &e) {
        q->done(makeError(GPG_ERR_UNEXPECTED),
                i18n("Caught unexpected exception in PrepSignCommand::Private::slotRecipientsResolved: %1", QString::fromLocal8Bit(e.what())));
    } catch (...) {
        q->done(makeError(GPG_ERR_UNEXPECTED), i18n("Caught unknown exception in PrepSignCommand::Private::slotRecipientsResolved"));
    }
    if (that) { // isn't this always deleted here and thus unnecessary?
        q->removeMemento(NewSignEncryptEMailController::mementoName());
    }
    cont->cancel();
}

void PrepSignCommand::Private::slotError(int err, const QString &details)
{
    q->done(err, details);
}

void PrepSignCommand::doCanceled()
{
    if (d->controller) {
        d->controller->cancel();
    }
}

#include "prepsigncommand.moc"
