/* -*- mode: c++; c-basic-offset:4 -*-
    commands/newcertificatesigningrequestcommand.cpp

    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2008 Klarälvdalens Datakonsult AB
    SPDX-FileCopyrightText: 2022 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include <config-kleopatra.h>

#include "newcertificatesigningrequestcommand.h"

#include "command_p.h"

#include <kleopatraapplication.h>

#include <dialogs/createcsrdialog.h>
#include <utils/csrutils.h>
#include <utils/keyparameters.h>

#include <settings.h>

#include <Libkleo/Formatting>

#include <KLocalizedString>

#include <QGpgME/KeyGenerationJob>
#include <QGpgME/Protocol>

#include <QProgressDialog>
#include <QSettings>

#include <gpgme++/context.h>
#include <gpgme++/keygenerationresult.h>

#include <kleopatra_debug.h>
#include <utils/qt6compat.h>

using namespace Kleo;
using namespace Kleo::Commands;
using namespace GpgME;
using namespace Qt::Literals;

class NewCertificateSigningRequestCommand::Private : public Command::Private
{
    friend class ::Kleo::Commands::NewCertificateSigningRequestCommand;
    NewCertificateSigningRequestCommand *q_func() const
    {
        return static_cast<NewCertificateSigningRequestCommand *>(q);
    }

public:
    explicit Private(NewCertificateSigningRequestCommand *qq, KeyListController *c)
        : Command::Private{qq, c}
    {
    }

    void getCertificateDetails();
    void createCSR();
    void showResult(const KeyGenerationResult &result, const QByteArray &request, const QString &auditLog);
    void showErrorDialog(const KeyGenerationResult &result, const QString &auditLog);

private:
    KeyParameters keyParameters;
    bool protectKeyWithPassword = false;
    QPointer<CreateCSRDialog> dialog;
    QPointer<QGpgME::Job> job;
    QPointer<QProgressDialog> progressDialog;
};

NewCertificateSigningRequestCommand::Private *NewCertificateSigningRequestCommand::d_func()
{
    return static_cast<Private *>(d.get());
}
const NewCertificateSigningRequestCommand::Private *NewCertificateSigningRequestCommand::d_func() const
{
    return static_cast<const Private *>(d.get());
}

#define d d_func()
#define q q_func()

void NewCertificateSigningRequestCommand::Private::getCertificateDetails()
{
    dialog = new CreateCSRDialog;
    dialog->setAttribute(Qt::WA_DeleteOnClose);
    applyWindowID(dialog);

    if (keyParameters.protocol() == KeyParameters::CMS) {
        dialog->setKeyParameters(keyParameters);
    }

    connect(dialog, &QDialog::accepted, q, [this]() {
        keyParameters = dialog->keyParameters();
        QMetaObject::invokeMethod(
            q,
            [this] {
                createCSR();
            },
            Qt::QueuedConnection);
    });
    connect(dialog, &QDialog::rejected, q, [this]() {
        canceled();
    });

    dialog->show();
}

void NewCertificateSigningRequestCommand::Private::createCSR()
{
    Q_ASSERT(keyParameters.protocol() == KeyParameters::CMS);

    auto keyGenJob = QGpgME::smime()->keyGenerationJob();
    if (!keyGenJob) {
        finished();
        return;
    }
    QGpgME::Job::context(keyGenJob)->setArmor(true);

    auto settings = KleopatraApplication::instance()->distributionSettings();
    if (settings) {
        keyParameters.setComment(settings->value(QStringLiteral("uidcomment"), {}).toString());
    }

    connect(keyGenJob, &QGpgME::KeyGenerationJob::result, q, [this](const KeyGenerationResult &result, const QByteArray &request, const QString &auditLog) {
        showResult(result, request, auditLog);
    });
    if (const Error err = keyGenJob->start(keyParameters.toString())) {
        error(i18n("Could not start key pair creation: %1", Formatting::errorAsString(err)));
        finished();
        return;
    } else {
        job = keyGenJob;
    }
    progressDialog = new QProgressDialog;
    progressDialog->setAttribute(Qt::WA_DeleteOnClose);
    applyWindowID(progressDialog);
    progressDialog->setModal(true);
    progressDialog->setWindowTitle(i18nc("@title", "Creating Key Pair..."));
    progressDialog->setLabelText(i18n("The process of creating a key requires large amounts of random numbers. This may require several minutes..."));
    progressDialog->setRange(0, 0);
    connect(progressDialog, &QProgressDialog::canceled, job, &QGpgME::Job::slotCancel);
    connect(job, &QGpgME::Job::done, q, [this]() {
        if (progressDialog) {
            progressDialog->accept();
        }
    });
    progressDialog->show();
}

void NewCertificateSigningRequestCommand::Private::showResult(const KeyGenerationResult &result, const QByteArray &request, const QString &auditLog)
{
    if (result.error()) {
        showErrorDialog(result, auditLog);
        return;
    }

    if (!result.error().isCanceled()) {
        saveCSR(request, keyParameters, parentWidgetOrView());
    }

    finished();
}

void NewCertificateSigningRequestCommand::Private::showErrorDialog(const KeyGenerationResult &result, const QString &auditLog)
{
    Q_UNUSED(auditLog)

    auto dialog = new QDialog;
    applyWindowID(dialog);
    dialog->setWindowTitle(i18nc("@title:window", "Error"));
    auto buttonBox = new QDialogButtonBox{QDialogButtonBox::Retry | QDialogButtonBox::Ok, dialog};
    const auto buttonCode = KMessageBox::createKMessageBox(dialog,
                                                           buttonBox,
                                                           QMessageBox::Critical,
                                                           xi18nc("@info",
                                                                  "<para>The creation of the certificate signing request failed.</para>"
                                                                  "<para>Error: <message>%1</message></para>",
                                                                  Formatting::errorAsString(result.error())),
                                                           {},
                                                           {},
                                                           nullptr,
                                                           {});
    if (buttonCode == QDialogButtonBox::Retry) {
        QMetaObject::invokeMethod(
            q,
            [this]() {
                getCertificateDetails();
            },
            Qt::QueuedConnection);
    } else {
        finished();
    }
}

NewCertificateSigningRequestCommand::NewCertificateSigningRequestCommand()
    : NewCertificateSigningRequestCommand(nullptr, nullptr)
{
}

NewCertificateSigningRequestCommand::NewCertificateSigningRequestCommand(QAbstractItemView *v, KeyListController *c)
    : Command(v, new Private(this, c))
{
}

NewCertificateSigningRequestCommand::~NewCertificateSigningRequestCommand() = default;

void NewCertificateSigningRequestCommand::doStart()
{
    const Kleo::Settings settings{};
    if (settings.cmsEnabled() && settings.cmsCertificateCreationAllowed()) {
        d->getCertificateDetails();
    } else {
        d->error(i18n("You are not allowed to create S/MIME certificate signing requests."));
        d->finished();
    }
}

void NewCertificateSigningRequestCommand::doCancel()
{
    if (d->dialog) {
        d->dialog->close();
    }
    if (d->job) {
        d->job->slotCancel();
    }
}

#undef d
#undef q
