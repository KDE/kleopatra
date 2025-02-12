/*
    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2007 Klarälvdalens Datakonsult AB

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include <config-kleopatra.h>

#include "prepencryptcommand.h"

#include <crypto/newsignencryptemailcontroller.h>

#include <Libkleo/KleoException>

#include <KLocalizedString>

#include <QPointer>

using namespace Kleo;
using namespace Kleo::Crypto;

class PrepEncryptCommand::Private : public QObject
{
    Q_OBJECT
private:
    friend class ::Kleo::PrepEncryptCommand;
    PrepEncryptCommand *const q;

public:
    explicit Private(PrepEncryptCommand *qq)
        : q(qq)
        , controller()
    {
    }

private:
    void checkForErrors() const;

public Q_SLOTS:
    void slotRecipientsResolved();
    void slotError(int, const QString &);

private:
    std::shared_ptr<NewSignEncryptEMailController> controller;
};

PrepEncryptCommand::PrepEncryptCommand()
    : AssuanCommandMixin<PrepEncryptCommand>()
    , d(new Private(this))
{
}

PrepEncryptCommand::~PrepEncryptCommand()
{
}

void PrepEncryptCommand::Private::checkForErrors() const
{
    if (!q->inputs().empty() || !q->outputs().empty() || !q->messages().empty())
        throw Exception(makeError(GPG_ERR_CONFLICT), i18n("INPUT/OUTPUT/MESSAGE may only be given after PREP_ENCRYPT"));

    if (q->numFiles())
        throw Exception(makeError(GPG_ERR_CONFLICT), i18n("PREP_ENCRYPT is an email mode command, connection seems to be in filemanager mode"));

    if (!q->senders().empty() && !q->informativeSenders())
        throw Exception(makeError(GPG_ERR_CONFLICT), i18n("SENDER may not be given prior to PREP_ENCRYPT, except with --info"));

    if (q->recipients().empty() || q->informativeRecipients())
        throw Exception(makeError(GPG_ERR_MISSING_VALUE), i18n("No recipients given, or only with --info"));
}

int PrepEncryptCommand::doStart()
{
    removeMemento(NewSignEncryptEMailController::mementoName());

    d->checkForErrors();

    d->controller.reset(new NewSignEncryptEMailController(shared_from_this()));
    d->controller->setEncrypting(true);

    const QString session = sessionTitle();
    if (!session.isEmpty()) {
        d->controller->setSubject(session);
    }

    if (hasOption("protocol"))
    // --protocol is optional for PREP_ENCRYPT
    {
        d->controller->setProtocol(checkProtocol(EMail));
    }

    d->controller->setSigning(hasOption("expect-sign"));

    QObject::connect(d->controller.get(), &NewSignEncryptEMailController::certificatesResolved, d.get(), &Private::slotRecipientsResolved);
    QObject::connect(d->controller.get(), SIGNAL(error(int, QString)), d.get(), SLOT(slotError(int, QString)));

    d->controller->startResolveCertificates(recipients(), senders());

    return 0;
}

void PrepEncryptCommand::Private::slotRecipientsResolved()
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
                i18n("Caught unexpected exception in PrepEncryptCommand::Private::slotRecipientsResolved: %1", QString::fromLocal8Bit(e.what())));
    } catch (...) {
        q->done(makeError(GPG_ERR_UNEXPECTED), i18n("Caught unknown exception in PrepEncryptCommand::Private::slotRecipientsResolved"));
    }
    if (that) { // isn't this always deleted here and thus unnecessary?
        q->removeMemento(NewSignEncryptEMailController::mementoName());
    }
    cont->cancel();
}

void PrepEncryptCommand::Private::slotError(int err, const QString &details)
{
    q->done(err, details);
}

void PrepEncryptCommand::doCanceled()
{
    if (d->controller) {
        d->controller->cancel();
    }
}

#include "prepencryptcommand.moc"
