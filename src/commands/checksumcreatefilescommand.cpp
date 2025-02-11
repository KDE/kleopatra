/* -*- mode: c++; c-basic-offset:4 -*-
    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2008 Klarälvdalens Datakonsult AB

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include <config-kleopatra.h>

#include "checksumcreatefilescommand.h"

#include "command_p.h"

#include <crypto/createchecksumscontroller.h>

#include <utils/filedialog.h>

#include <Libkleo/Stl_Util>

#include "kleopatra_debug.h"
#include <KLocalizedString>

#include <exception>

using namespace Kleo;
using namespace Kleo::Commands;
using namespace Kleo::Crypto;

class ChecksumCreateFilesCommand::Private : public Command::Private
{
    friend class ::Kleo::Commands::ChecksumCreateFilesCommand;
    ChecksumCreateFilesCommand *q_func() const
    {
        return static_cast<ChecksumCreateFilesCommand *>(q);
    }

public:
    explicit Private(ChecksumCreateFilesCommand *qq, KeyListController *c);
    ~Private() override;

    QStringList selectFiles() const;

    void init();

private:
    void slotControllerDone()
    {
        finished();
    }
    void slotControllerError(int, const QString &)
    {
        finished();
    }

private:
    QStringList files;
    std::shared_ptr<const ExecutionContext> shared_qq;
    CreateChecksumsController controller;
};

ChecksumCreateFilesCommand::Private *ChecksumCreateFilesCommand::d_func()
{
    return static_cast<Private *>(d.get());
}
const ChecksumCreateFilesCommand::Private *ChecksumCreateFilesCommand::d_func() const
{
    return static_cast<const Private *>(d.get());
}

#define d d_func()
#define q q_func()

ChecksumCreateFilesCommand::Private::Private(ChecksumCreateFilesCommand *qq, KeyListController *c)
    : Command::Private(qq, c)
    , files()
    , shared_qq(qq, [](ChecksumCreateFilesCommand *) {})
    , controller()
{
    controller.setAllowAddition(true);
}

ChecksumCreateFilesCommand::Private::~Private()
{
    qCDebug(KLEOPATRA_LOG);
}

ChecksumCreateFilesCommand::ChecksumCreateFilesCommand(KeyListController *c)
    : Command(new Private(this, c))
{
    d->init();
}

ChecksumCreateFilesCommand::ChecksumCreateFilesCommand(QAbstractItemView *v, KeyListController *c)
    : Command(v, new Private(this, c))
{
    d->init();
}

ChecksumCreateFilesCommand::ChecksumCreateFilesCommand(const QStringList &files, KeyListController *c)
    : Command(new Private(this, c))
{
    d->init();
    d->files = files;
}

ChecksumCreateFilesCommand::ChecksumCreateFilesCommand(const QStringList &files, QAbstractItemView *v, KeyListController *c)
    : Command(v, new Private(this, c))
{
    d->init();
    d->files = files;
}

void ChecksumCreateFilesCommand::Private::init()
{
    controller.setExecutionContext(shared_qq);
    connect(&controller, &Crypto::Controller::done, q, [this]() {
        slotControllerDone();
    });
    connect(&controller, &Crypto::Controller::error, q, [this](int err, const QString &details) {
        slotControllerError(err, details);
    });
}

ChecksumCreateFilesCommand::~ChecksumCreateFilesCommand()
{
    qCDebug(KLEOPATRA_LOG);
}

void ChecksumCreateFilesCommand::setFiles(const QStringList &files)
{
    d->files = files;
}

void ChecksumCreateFilesCommand::doStart()
{
    try {
        if (d->files.empty()) {
            d->files = d->selectFiles();
        }
        if (d->files.empty()) {
            d->finished();
            return;
        }

        d->controller.setFiles(d->files);
        d->controller.start();

    } catch (const std::exception &e) {
        d->information(i18n("An error occurred: %1", QString::fromLocal8Bit(e.what())), i18n("Create Checksum Files Error"));
        d->finished();
    }
}

void ChecksumCreateFilesCommand::doCancel()
{
    qCDebug(KLEOPATRA_LOG);
    d->controller.cancel();
}

QStringList ChecksumCreateFilesCommand::Private::selectFiles() const
{
    return FileDialog::getOpenFileNames(parentWidgetOrView(), i18n("Select One or More Files to Create Checksums For"), QStringLiteral("chk"));
}

#undef d
#undef q

#include "moc_checksumcreatefilescommand.cpp"
