/*
    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2008 Klarälvdalens Datakonsult AB

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include <config-kleopatra.h>

#include "checksumverifyfilescommand.h"

#include "command_p.h"

#include <crypto/verifychecksumscontroller.h>

#include <utils/filedialog.h>

#include <Libkleo/Stl_Util>

#include "kleopatra_debug.h"
#include <KLocalizedString>

#include <exception>

using namespace Kleo;
using namespace Kleo::Commands;
using namespace Kleo::Crypto;

class ChecksumVerifyFilesCommand::Private : public Command::Private
{
    friend class ::Kleo::Commands::ChecksumVerifyFilesCommand;
    ChecksumVerifyFilesCommand *q_func() const
    {
        return static_cast<ChecksumVerifyFilesCommand *>(q);
    }

public:
    explicit Private(ChecksumVerifyFilesCommand *qq, KeyListController *c);
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
    VerifyChecksumsController controller;
};

ChecksumVerifyFilesCommand::Private *ChecksumVerifyFilesCommand::d_func()
{
    return static_cast<Private *>(d.get());
}
const ChecksumVerifyFilesCommand::Private *ChecksumVerifyFilesCommand::d_func() const
{
    return static_cast<const Private *>(d.get());
}

#define d d_func()
#define q q_func()

ChecksumVerifyFilesCommand::Private::Private(ChecksumVerifyFilesCommand *qq, KeyListController *c)
    : Command::Private(qq, c)
    , files()
    , shared_qq(qq, [](ChecksumVerifyFilesCommand *) {})
    , controller()
{
}

ChecksumVerifyFilesCommand::Private::~Private()
{
    qCDebug(KLEOPATRA_LOG);
}

ChecksumVerifyFilesCommand::ChecksumVerifyFilesCommand(KeyListController *c)
    : Command(new Private(this, c))
{
    d->init();
}

ChecksumVerifyFilesCommand::ChecksumVerifyFilesCommand(QAbstractItemView *v, KeyListController *c)
    : Command(v, new Private(this, c))
{
    d->init();
}

ChecksumVerifyFilesCommand::ChecksumVerifyFilesCommand(const QStringList &files, KeyListController *c)
    : Command(new Private(this, c))
{
    d->init();
    d->files = files;
}

ChecksumVerifyFilesCommand::ChecksumVerifyFilesCommand(const QStringList &files, QAbstractItemView *v, KeyListController *c)
    : Command(v, new Private(this, c))
{
    d->init();
    d->files = files;
}

void ChecksumVerifyFilesCommand::Private::init()
{
    controller.setExecutionContext(shared_qq);
    connect(&controller, &Controller::done, q, [this]() {
        slotControllerDone();
    });
    connect(&controller, &Controller::error, q, [this](int err, const QString &details) {
        slotControllerError(err, details);
    });
}

ChecksumVerifyFilesCommand::~ChecksumVerifyFilesCommand()
{
    qCDebug(KLEOPATRA_LOG);
}

void ChecksumVerifyFilesCommand::setFiles(const QStringList &files)
{
    d->files = files;
}

void ChecksumVerifyFilesCommand::doStart()
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
        d->information(i18n("An error occurred: %1", QString::fromLocal8Bit(e.what())), i18n("Verify Checksum Files Error"));
        d->finished();
    }
}

void ChecksumVerifyFilesCommand::doCancel()
{
    qCDebug(KLEOPATRA_LOG);
    d->controller.cancel();
}

QStringList ChecksumVerifyFilesCommand::Private::selectFiles() const
{
    return FileDialog::getOpenFileNames(parentWidgetOrView(), i18n("Select One or More Checksum Files"), QStringLiteral("chk"));
}

#undef d
#undef q

#include "moc_checksumverifyfilescommand.cpp"
