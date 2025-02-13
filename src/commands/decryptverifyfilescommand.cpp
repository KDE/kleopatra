/*
    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2008 Klarälvdalens Datakonsult AB

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include <config-kleopatra.h>

#include "decryptverifyfilescommand.h"
#include "viewemailfilescommand.h"

#include "command_p.h"
#include "fileoperationspreferences.h"

#include "crypto/autodecryptverifyfilescontroller.h"

#include <utils/filedialog.h>

#include <Libkleo/Classify>
#include <Libkleo/Stl_Util>

#include "kleopatra_debug.h"
#include <KLocalizedString>

#include <exception>

using namespace Kleo;
using namespace Kleo::Commands;
using namespace Kleo::Crypto;

class DecryptVerifyFilesCommand::Private : public Command::Private
{
    friend class ::Kleo::Commands::DecryptVerifyFilesCommand;
    DecryptVerifyFilesCommand *q_func() const
    {
        return static_cast<DecryptVerifyFilesCommand *>(q);
    }

public:
    explicit Private(DecryptVerifyFilesCommand *qq, KeyListController *c, bool forceManualMode = false);
    ~Private() override;

    QStringList selectFiles() const;

    void init();

private:
    void finishIfEverythingIsDone()
    {
        if (files.empty() && emailFiles.empty()) {
            finished();
        }
    }

    void slotControllerDone()
    {
        files.clear();
        finishIfEverythingIsDone();
    }

    void slotControllerError(int, const QString &msg)
    {
        KMessageBox::error(parentWidgetOrView(), msg, i18nc("@title:window", "Decrypt/Verify Failed"));
        finishIfEverythingIsDone();
    }

private:
    QStringList files;
    QStringList emailFiles;
    std::shared_ptr<const ExecutionContext> shared_qq;
    AutoDecryptVerifyFilesController *mController;
};

DecryptVerifyFilesCommand::Private *DecryptVerifyFilesCommand::d_func()
{
    return static_cast<Private *>(d.get());
}
const DecryptVerifyFilesCommand::Private *DecryptVerifyFilesCommand::d_func() const
{
    return static_cast<const Private *>(d.get());
}

#define d d_func()
#define q q_func()

DecryptVerifyFilesCommand::Private::Private(DecryptVerifyFilesCommand *qq, KeyListController *c, bool forceManualMode)
    : Command::Private(qq, c)
    , files()
    , shared_qq(qq, [](DecryptVerifyFilesCommand *) {})
{
    mController = new AutoDecryptVerifyFilesController();
}

DecryptVerifyFilesCommand::Private::~Private()
{
    qCDebug(KLEOPATRA_LOG);
    delete mController;
}

DecryptVerifyFilesCommand::DecryptVerifyFilesCommand(KeyListController *c)
    : Command(new Private(this, c))
{
    d->init();
}

DecryptVerifyFilesCommand::DecryptVerifyFilesCommand(QAbstractItemView *v, KeyListController *c)
    : Command(v, new Private(this, c))
{
    d->init();
}

DecryptVerifyFilesCommand::DecryptVerifyFilesCommand(const QStringList &files, KeyListController *c, bool forceManualMode)
    : Command(new Private(this, c, forceManualMode))
{
    d->init();
    d->files = files;
}

DecryptVerifyFilesCommand::DecryptVerifyFilesCommand(const QStringList &files, QAbstractItemView *v, KeyListController *c)
    : Command(v, new Private(this, c))
{
    d->init();
    d->files = files;
}

void DecryptVerifyFilesCommand::Private::init()
{
    mController->setExecutionContext(shared_qq);
    connect(mController, &Controller::done, q, [this]() {
        slotControllerDone();
    });
    connect(mController, &Controller::error, q, [this](int err, const QString &details) {
        slotControllerError(err, details);
    });
}

DecryptVerifyFilesCommand::~DecryptVerifyFilesCommand()
{
    qCDebug(KLEOPATRA_LOG);
}

void DecryptVerifyFilesCommand::setFiles(const QStringList &files)
{
    d->files = files;
}

void DecryptVerifyFilesCommand::setOperation(DecryptVerifyOperation op)
{
    try {
        d->mController->setOperation(op);
    } catch (...) {
    }
}

DecryptVerifyOperation DecryptVerifyFilesCommand::operation() const
{
    return d->mController->operation();
}

void DecryptVerifyFilesCommand::doStart()
{
    try {
        if (d->files.empty()) {
            d->files = d->selectFiles();
        }
        if (d->files.empty()) {
            d->finished();
            return;
        }

        for (const auto &file : std::as_const(d->files)) {
            const unsigned int classification = classify(file);
            if (classification & Class::MimeFile) {
                d->emailFiles << file;
                d->files.removeAll(file);
            }
        }

        if (!d->emailFiles.empty()) {
            const auto viewEmailCommand = new ViewEmailFilesCommand(d->emailFiles, nullptr);
            connect(viewEmailCommand, &ViewEmailFilesCommand::finished, this, [this] {
                d->emailFiles.clear();
                d->finishIfEverythingIsDone();
            });
            viewEmailCommand->start();
        }

        if (d->files.empty()) {
            return;
        }

        d->mController->setFiles(d->files);
        d->mController->start();

    } catch (const std::exception &e) {
        d->information(i18n("An error occurred: %1", QString::fromLocal8Bit(e.what())), i18n("Decrypt/Verify Files Error"));
        d->finished();
    }
}

void DecryptVerifyFilesCommand::doCancel()
{
    qCDebug(KLEOPATRA_LOG);
    d->mController->cancel();
}

QStringList DecryptVerifyFilesCommand::Private::selectFiles() const
{
    return FileDialog::getOpenFileNames(parentWidgetOrView(), i18n("Select One or More Files to Decrypt and/or Verify"), QStringLiteral("enc"));
}

#undef d
#undef q

#include "moc_decryptverifyfilescommand.cpp"
