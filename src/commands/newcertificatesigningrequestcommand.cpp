/*
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

#include <settings.h>

#include <Libkleo/Formatting>
#include <Libkleo/KeyCache>
#include <Libkleo/KeyParameters>

#include <KFileUtils>

#include <QGpgME/DN>
#include <QGpgME/KeyGenerationJob>
#include <QGpgME/Protocol>
#include <qgpgme/qgpgme_version.h>

#include <QDir>
#include <QFile>
#include <QProgressDialog>
#include <QSettings>

#include <gpgme++/context.h>
#include <gpgme++/keygenerationresult.h>

#include <kleopatra_debug.h>

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

static QString usageText(KeyUsage usage)
{
    if (usage.canEncrypt()) {
        return usage.canSign() ? u"sign_encrypt"_s : u"encrypt"_s;
    }
    return u"sign"_s;
}

void NewCertificateSigningRequestCommand::Private::showResult(const KeyGenerationResult &result, const QByteArray &request, const QString &auditLog)
{
    if (result.error().isCanceled()) {
        finished();
        return;
#if QGPGME_VERSION >= QT_VERSION_CHECK(2, 0, 0)
    } else if (result.error().isError()) {
#else
    } else if (result.error().code()) {
#endif
        showErrorDialog(result, auditLog);
        return;
    }

    QString filename = QStringLiteral("request_%1_%2.p10").arg(usageText(keyParameters.keyUsage()), keyParameters.emails().front());
    const QDir saveLocation{QStandardPaths::writableLocation(QStandardPaths::DocumentsLocation)};
    if (saveLocation.exists(filename)) {
        filename = KFileUtils::suggestName(QUrl::fromLocalFile(saveLocation.path()), filename);
    }
    QFile file(saveLocation.absoluteFilePath(filename));
    if (!file.open(QIODevice::WriteOnly)) {
        error(xi18nc("@info", "Could not write the request to the file <filename>%1</filename>: %2", file.fileName(), file.errorString()));
        finished();
        return;
    }
    file.write(request);
    file.close();
    success(xi18nc("@info",
                   "<para>Successfully wrote request to <filename>%1</filename>.</para>"
                   "<para>You should now send the request to the Certification Authority (CA).</para>",
                   file.fileName()));
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

#include "moc_newcertificatesigningrequestcommand.cpp"
