/*
    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2010 Klarälvdalens Datakonsult AB

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include <config-kleopatra.h>

#include "createchecksumscommand.h"

#include <crypto/createchecksumscontroller.h>

#include <Libkleo/KleoException>

#include <KLocalizedString>

using namespace Kleo;
using namespace Kleo::Crypto;

class CreateChecksumsCommand::Private
{
private:
    friend class ::Kleo::CreateChecksumsCommand;
    CreateChecksumsCommand *const q;

public:
    explicit Private(CreateChecksumsCommand *qq)
        : q(qq)
        , controller()
    {
    }

private:
    void checkForErrors() const;

private:
    std::shared_ptr<CreateChecksumsController> controller;
};

CreateChecksumsCommand::CreateChecksumsCommand()
    : AssuanCommandMixin<CreateChecksumsCommand>()
    , d(new Private(this))
{
}

CreateChecksumsCommand::~CreateChecksumsCommand()
{
}

void CreateChecksumsCommand::Private::checkForErrors() const
{
    if (!q->numFiles())
        throw Exception(makeError(GPG_ERR_ASS_NO_INPUT), i18n("At least one FILE must be present"));
}

int CreateChecksumsCommand::doStart()
{
    d->checkForErrors();

    d->controller.reset(new CreateChecksumsController(shared_from_this()));

    d->controller->setAllowAddition(hasOption("allow-addition"));

    d->controller->setFiles(fileNames());

    connect(
        d->controller.get(),
        &Controller::done,
        this,
        [this]() {
            done();
        },
        Qt::QueuedConnection);
    connect(
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

void CreateChecksumsCommand::doCanceled()
{
    if (d->controller) {
        d->controller->cancel();
    }
}

#include "moc_createchecksumscommand.cpp"
