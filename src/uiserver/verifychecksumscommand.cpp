/*
    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2010 Klarälvdalens Datakonsult AB

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include <config-kleopatra.h>

#include "verifychecksumscommand.h"

#ifndef QT_NO_DIRMODEL

#include <crypto/verifychecksumscontroller.h>

#include <Libkleo/KleoException>

#include <KLocalizedString>

using namespace Kleo;
using namespace Kleo::Crypto;

class VerifyChecksumsCommand::Private
{
private:
    friend class ::Kleo::VerifyChecksumsCommand;
    VerifyChecksumsCommand *const q;

public:
    explicit Private(VerifyChecksumsCommand *qq)
        : q(qq)
        , controller()
    {
    }

private:
    void checkForErrors() const;

private:
    std::shared_ptr<VerifyChecksumsController> controller;
};

VerifyChecksumsCommand::VerifyChecksumsCommand()
    : AssuanCommandMixin<VerifyChecksumsCommand>()
    , d(new Private(this))
{
}

VerifyChecksumsCommand::~VerifyChecksumsCommand()
{
}

void VerifyChecksumsCommand::Private::checkForErrors() const
{
    if (!q->numFiles())
        throw Exception(makeError(GPG_ERR_ASS_NO_INPUT), i18n("At least one FILE must be present"));
}

int VerifyChecksumsCommand::doStart()
{
    d->checkForErrors();

    d->controller.reset(new VerifyChecksumsController(shared_from_this()));

    d->controller->setFiles(fileNames());

    QObject::connect(
        d->controller.get(),
        &Controller::done,
        this,
        [this]() {
            done();
        },
        Qt::QueuedConnection);
    QObject::connect(
        d->controller.get(),
        &Controller::error,
        this,
        [this](int err, const QString &details) {
            done(err, details);
        },
        Qt::QueuedConnection);

    d->controller->start();

    return 0;
}

void VerifyChecksumsCommand::doCanceled()
{
    if (d->controller) {
        d->controller->cancel();
    }
}

#endif // QT_NO_DIRMODEL

#include "moc_verifychecksumscommand.cpp"
