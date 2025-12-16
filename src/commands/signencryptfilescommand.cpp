/*
    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2008 Klarälvdalens Datakonsult AB

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include <config-kleopatra.h>

#include "signencryptfilescommand.h"

#include "command_p.h"

#include <crypto/signencryptfilescontroller.h>

#include <utils/filedialog.h>

#include <Libkleo/Stl_Util>

#include "kleopatra_debug.h"
#include <KLocalizedString>

#include <exception>

using namespace Kleo;
using namespace Kleo::Commands;
using namespace Kleo::Crypto;

class SignEncryptFilesCommand::Private : public Command::Private
{
    friend class ::Kleo::Commands::SignEncryptFilesCommand;
    SignEncryptFilesCommand *q_func() const
    {
        return static_cast<SignEncryptFilesCommand *>(q);
    }

public:
    explicit Private(SignEncryptFilesCommand *qq, KeyListController *c);
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
    SignEncryptFilesController controller;
};

SignEncryptFilesCommand::Private *SignEncryptFilesCommand::d_func()
{
    return static_cast<Private *>(d.get());
}
const SignEncryptFilesCommand::Private *SignEncryptFilesCommand::d_func() const
{
    return static_cast<const Private *>(d.get());
}

#define d d_func()
#define q q_func()

SignEncryptFilesCommand::Private::Private(SignEncryptFilesCommand *qq, KeyListController *c)
    : Command::Private(qq, c)
    , files()
    , shared_qq(qq, [](SignEncryptFilesCommand *) {})
    , controller()
{
    controller.setOperationMode(SignEncryptFilesController::SignAllowed //
                                | SignEncryptFilesController::EncryptAllowed //
                                | SignEncryptFilesController::ArchiveAllowed);
}

SignEncryptFilesCommand::Private::~Private()
{
    qCDebug(KLEOPATRA_LOG) << q << __func__;
}

SignEncryptFilesCommand::SignEncryptFilesCommand(KeyListController *c)
    : Command(new Private(this, c))
{
    d->init();
}

SignEncryptFilesCommand::SignEncryptFilesCommand(QAbstractItemView *v, KeyListController *c)
    : Command(v, new Private(this, c))
{
    d->init();
}

SignEncryptFilesCommand::SignEncryptFilesCommand(const QStringList &files, KeyListController *c)
    : Command(new Private(this, c))
{
    d->init();
    d->files = files;
}

SignEncryptFilesCommand::SignEncryptFilesCommand(const QStringList &files, QAbstractItemView *v, KeyListController *c)
    : Command(v, new Private(this, c))
{
    d->init();
    d->files = files;
}

void SignEncryptFilesCommand::Private::init()
{
    controller.setExecutionContext(shared_qq);
    connect(&controller, &Controller::done, q, [this]() {
        slotControllerDone();
    });
    connect(&controller, &Controller::error, q, [this](int err, const QString &details) {
        slotControllerError(err, details);
    });
}

SignEncryptFilesCommand::~SignEncryptFilesCommand()
{
    qCDebug(KLEOPATRA_LOG) << this << __func__;
}

void SignEncryptFilesCommand::setFiles(const QStringList &files)
{
    d->files = files;
}

void SignEncryptFilesCommand::setSigningPolicy(Policy policy)
{
    unsigned int mode = d->controller.operationMode();
    mode &= ~SignEncryptFilesController::SignMask;
    switch (policy) {
    case NoPolicy:
    case Allow:
        mode |= SignEncryptFilesController::SignAllowed;
        break;
    case Deny:
        mode |= SignEncryptFilesController::SignDisallowed;
        break;
    case Force:
        mode |= SignEncryptFilesController::SignSelected;
        break;
    }
    try {
        d->controller.setOperationMode(mode);
    } catch (...) {
    }
}

Policy SignEncryptFilesCommand::signingPolicy() const
{
    const unsigned int mode = d->controller.operationMode();
    switch (mode & SignEncryptFilesController::SignMask) {
    default:
        Q_ASSERT(!"This should not happen!");
        return NoPolicy;
    case SignEncryptFilesController::SignAllowed:
        return Allow;
    case SignEncryptFilesController::SignSelected:
        return Force;
    case SignEncryptFilesController::SignDisallowed:
        return Deny;
    }
}

void SignEncryptFilesCommand::setEncryptionPolicy(Policy policy)
{
    unsigned int mode = d->controller.operationMode();
    mode &= ~SignEncryptFilesController::EncryptMask;
    switch (policy) {
    case NoPolicy:
    case Allow:
        mode |= SignEncryptFilesController::EncryptAllowed;
        break;
    case Deny:
        mode |= SignEncryptFilesController::EncryptDisallowed;
        break;
    case Force:
        mode |= SignEncryptFilesController::EncryptSelected;
        break;
    }
    try {
        d->controller.setOperationMode(mode);
    } catch (...) {
    }
}

Policy SignEncryptFilesCommand::encryptionPolicy() const
{
    const unsigned int mode = d->controller.operationMode();
    switch (mode & SignEncryptFilesController::EncryptMask) {
    default:
        Q_ASSERT(!"This should not happen!");
        return NoPolicy;
    case SignEncryptFilesController::EncryptAllowed:
        return Allow;
    case SignEncryptFilesController::EncryptSelected:
        return Force;
    case SignEncryptFilesController::EncryptDisallowed:
        return Deny;
    }
}

void SignEncryptFilesCommand::setArchivePolicy(Policy policy)
{
    unsigned int mode = d->controller.operationMode();
    mode &= ~SignEncryptFilesController::ArchiveMask;
    switch (policy) {
    case NoPolicy:
    case Allow:
        mode |= SignEncryptFilesController::ArchiveAllowed;
        break;
    case Deny:
        mode |= SignEncryptFilesController::ArchiveDisallowed;
        break;
    case Force:
        mode |= SignEncryptFilesController::ArchiveForced;
        break;
    }
    d->controller.setOperationMode(mode);
}

Policy SignEncryptFilesCommand::archivePolicy() const
{
    const unsigned int mode = d->controller.operationMode();
    switch (mode & SignEncryptFilesController::ArchiveMask) {
    case SignEncryptFilesController::ArchiveAllowed:
        return Allow;
    case SignEncryptFilesController::ArchiveForced:
        return Force;
    case SignEncryptFilesController::ArchiveDisallowed:
        return Deny;
    default:
        Q_ASSERT(!"This should not happen!");
        return NoPolicy;
    }
}

void SignEncryptFilesCommand::setProtocol(GpgME::Protocol proto)
{
    d->controller.setProtocol(proto);
}

GpgME::Protocol SignEncryptFilesCommand::protocol() const
{
    return d->controller.protocol();
}

void SignEncryptFilesCommand::doStart()
{
    try {
        if (d->files.empty()) {
            d->files = selectFiles();
        }
        if (d->files.empty()) {
            d->finished();
            return;
        }

        d->controller.setFiles(d->files);
        d->controller.start();

    } catch (const std::exception &e) {
        d->information(i18n("An error occurred: %1", QString::fromLocal8Bit(e.what())), i18n("Sign/Encrypt Files Error"));
        d->finished();
    }
}

void SignEncryptFilesCommand::doCancel()
{
    qCDebug(KLEOPATRA_LOG) << this << __func__;
    d->controller.cancel();
}

QStringList SignEncryptFilesCommand::selectFiles() const
{
    return FileDialog::getOpenFileNames(d->parentWidgetOrView(), i18n("Select One or More Files to Sign and/or Encrypt"), QStringLiteral("enc"));
}

#undef d
#undef q

#include "moc_signencryptfilescommand.cpp"
