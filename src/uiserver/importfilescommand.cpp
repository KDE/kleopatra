/* -*- mode: c++; c-basic-offset:4 -*-
    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2008 Klarälvdalens Datakonsult AB

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include <config-kleopatra.h>

#include "importfilescommand.h"

#include <commands/importcertificatefromfilecommand.h>

#include <Libkleo/KleoException>

#include <gpgme++/key.h>

#include <gpg-error.h>

#include <algorithm>
#include <string>

using namespace Kleo;

class ImportFilesCommand::Private
{
    friend class ::Kleo::ImportFilesCommand;
    ImportFilesCommand *const q;

public:
    Private(ImportFilesCommand *qq)
        : q(qq)
        , command(nullptr)
    {
        Q_SET_OBJECT_NAME(command);
        command.setAutoDelete(false);

        connect(&command, SIGNAL(finished()), q, SLOT(slotCommandFinished()));
        connect(&command, SIGNAL(canceled()), q, SLOT(slotCommandCanceled()));
    }

private:
    void slotCommandFinished()
    {
        q->done();
    }
    void slotCommandCanceled()
    {
        q->done(makeError(GPG_ERR_CANCELED));
    }

private:
    ImportCertificateFromFileCommand command;
};

ImportFilesCommand::ImportFilesCommand()
    : QObject()
    , AssuanCommandMixin<ImportFilesCommand>()
    , d(new Private(this))
{
}

ImportFilesCommand::~ImportFilesCommand()
{
}

int ImportFilesCommand::doStart()
{
    d->command.setParentWId(parentWId());
    d->command.setFiles(fileNames());
    d->command.start();

    return 0;
}

void ImportFilesCommand::doCanceled()
{
    d->command.cancel();
}

#include "moc_importfilescommand.cpp"
