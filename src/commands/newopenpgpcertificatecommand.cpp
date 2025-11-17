/*
    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2008 Klarälvdalens Datakonsult AB
    SPDX-FileCopyrightText: 2022 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include <config-kleopatra.h>

#include "newopenpgpcertificatecommand.h"

#include "command_p.h"

#include "kleopatraapplication.h"
#include "utils/emptypassphraseprovider.h"
#include "utils/userinfo.h"

#include <settings.h>

#include <Libkleo/AuditLogEntry>
#include <Libkleo/Formatting>
#include <Libkleo/KeyCache>
#include <Libkleo/KeyParameters>
#include <Libkleo/OpenPGPCertificateCreationDialog>

#include <KConfigGroup>
#include <KLocalizedString>
#include <KMessageBox>
#include <KSharedConfig>

#include <QGpgME/KeyGenerationJob>
#include <QGpgME/Protocol>
#include <QGpgME/QuickJob>

#include <QProgressDialog>
#include <QSettings>

#include <gpgme++/context.h>
#include <gpgme++/keygenerationresult.h>

#include <kleopatra_debug.h>

using namespace Kleo;
using namespace GpgME;

class NewOpenPGPCertificateCommand::Private : public Command::Private
{
    friend class ::Kleo::NewOpenPGPCertificateCommand;
    NewOpenPGPCertificateCommand *q_func() const
    {
        return static_cast<NewOpenPGPCertificateCommand *>(q);
    }

public:
    explicit Private(NewOpenPGPCertificateCommand *qq, KeyListController *c)
        : Command::Private{qq, c}
    {
    }

    void getCertificateDetails();
    void createCertificate();
    void handleKeyGenerationResult(const KeyGenerationResult &result, const AuditLogEntry &auditLog);
    void showErrorDialog(const KeyGenerationResult &result, const AuditLogEntry &auditLog = {});

private:
    KeyParameters keyParameters;
    bool protectKeyWithPassword = false;
    bool teamKey = false;
    EmptyPassphraseProvider emptyPassphraseProvider;
    QPointer<OpenPGPCertificateCreationDialog> detailsDialog;
    QPointer<QGpgME::Job> job;
    QPointer<QProgressDialog> progressDialog;
    std::shared_ptr<KeyCacheAutoRefreshSuspension> keyCacheAutoRefreshSuspension;
};

NewOpenPGPCertificateCommand::Private *NewOpenPGPCertificateCommand::d_func()
{
    return static_cast<Private *>(d.get());
}
const NewOpenPGPCertificateCommand::Private *NewOpenPGPCertificateCommand::d_func() const
{
    return static_cast<const Private *>(d.get());
}

#define d d_func()
#define q q_func()

void NewOpenPGPCertificateCommand::Private::getCertificateDetails()
{
    detailsDialog = new OpenPGPCertificateCreationDialog;
    detailsDialog->setAttribute(Qt::WA_DeleteOnClose);
    detailsDialog->showTeamKeyOption(true);
    applyWindowID(detailsDialog);

    if (keyParameters.protocol() == KeyParameters::NoProtocol) {
        const auto settings = Kleo::Settings{};
        const KConfigGroup config{KSharedConfig::openConfig(), QLatin1StringView("CertificateCreationWizard")};
        // prefer the last used name and email address over the values retrieved from the system
        detailsDialog->setName(config.readEntry("NAME", QString{}));
        if (detailsDialog->name().isEmpty() && settings.prefillName()) {
            detailsDialog->setName(userFullName());
        }
        detailsDialog->setEmail(config.readEntry("EMAIL", QString{}));
        if (detailsDialog->email().isEmpty() && settings.prefillEmail()) {
            detailsDialog->setEmail(userEmailAddress());
        }
    } else {
        detailsDialog->setKeyParameters(keyParameters);
        detailsDialog->setProtectKeyWithPassword(protectKeyWithPassword);
    }

    connect(detailsDialog, &QDialog::accepted, q, [this]() {
        keyParameters = detailsDialog->keyParameters();
        protectKeyWithPassword = detailsDialog->protectKeyWithPassword();
        teamKey = detailsDialog->isTeamKey();
        QMetaObject::invokeMethod(
            q,
            [this] {
                createCertificate();
            },
            Qt::QueuedConnection);
    });
    connect(detailsDialog, &QDialog::rejected, q, [this]() {
        canceled();
    });

    detailsDialog->show();
}

void NewOpenPGPCertificateCommand::Private::createCertificate()
{
    Q_ASSERT(keyParameters.protocol() == KeyParameters::OpenPGP);

    auto keyGenJob = QGpgME::openpgp()->keyGenerationJob();
    if (!keyGenJob) {
        finished();
        return;
    }
    if (!protectKeyWithPassword) {
        auto ctx = QGpgME::Job::context(keyGenJob);
        ctx->setPassphraseProvider(&emptyPassphraseProvider);
        ctx->setPinentryMode(Context::PinentryLoopback);
    }

    auto settings = KleopatraApplication::instance()->distributionSettings();
    if (settings) {
        keyParameters.setComment(settings->value(QStringLiteral("uidcomment"), {}).toString());
    }

    keyCacheAutoRefreshSuspension = KeyCache::mutableInstance()->suspendAutoRefresh();

    connect(keyGenJob,
            &QGpgME::KeyGenerationJob::result,
            q,
            [this](const KeyGenerationResult &result, const QByteArray &, const QString &auditLogAsHtml, const GpgME::Error &auditLogError) {
                QMetaObject::invokeMethod(
                    q,
                    [this, result, auditLogAsHtml, auditLogError] {
                        handleKeyGenerationResult(result, AuditLogEntry{auditLogAsHtml, auditLogError});
                    },
                    Qt::QueuedConnection);
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

void NewOpenPGPCertificateCommand::Private::handleKeyGenerationResult(const KeyGenerationResult &result, const AuditLogEntry &auditLog)
{
    if (result.error().isCanceled()) {
        finished();
        return;
    }

    // Ensure that we have the key in the cache
    Key key;
    if (!result.error().code() && result.fingerprint()) {
        std::unique_ptr<Context> ctx{Context::createForProtocol(OpenPGP)};
        if (ctx) {
            Error err;
            ctx->addKeyListMode(KeyListMode::Validate | KeyListMode::Signatures | KeyListMode::SignatureNotations);
            key = ctx->key(result.fingerprint(), err, /*secret=*/true);
            if (!key.isNull()) {
                KeyCache::mutableInstance()->insert(key);
            }
        }
    }

    if (key.isNull()) {
        showErrorDialog(result, auditLog);
        return;
    }

    if (teamKey) {
        auto quickJob = std::unique_ptr<QGpgME::QuickJob>(QGpgME::openpgp()->quickJob());
        auto flags = Context::CreationFlags::CreateSign;
        if (!protectKeyWithPassword) {
            flags |= GpgME::Context::CreationFlags::CreateNoPassword;
        }
        connect(quickJob.get(), &QGpgME::QuickJob::result, q, [this, result](const auto &err) {
            if (err) {
                error(i18nc("@info", "Failed to create signing subkey: %1", Formatting::errorAsString(err)));
                finished();
                return;
            }

            if (err.isCanceled()) {
                finished();
                return;
            }

            // Ensure that we have the key in the cache
            Key key;
            if (!result.error().code() && result.fingerprint()) {
                std::unique_ptr<Context> ctx{Context::createForProtocol(OpenPGP)};
                if (ctx) {
                    Error err;
                    ctx->addKeyListMode(KeyListMode::Validate | KeyListMode::Signatures | KeyListMode::SignatureNotations);
                    key = ctx->key(result.fingerprint(), err, /*secret=*/true);
                    if (!key.isNull()) {
                        KeyCache::mutableInstance()->insert(key);
                    }
                }
            }

            success(xi18nc("@info",
                           "<para>A new OpenPGP certificate was created successfully.</para>"
                           "<para>Fingerprint of the new certificate: %1</para>",
                           Formatting::prettyID(key.primaryFingerprint())));
            finished();
        });
        auto err = quickJob->startAddSubkey(key, QByteArray::fromStdString(key.subkey(0).algoName()), {}, flags);
        if (err) {
            error(i18nc("@info", "Failed to create signing subkey: %1", Formatting::errorAsString(err)));
            finished();
            return;
        }
        quickJob.release();
    } else {
        success(xi18nc("@info",
                       "<para>A new OpenPGP certificate was created successfully.</para>"
                       "<para>Fingerprint of the new certificate: %1</para>",
                       Formatting::prettyID(key.primaryFingerprint())));
        finished();
    }
}

void NewOpenPGPCertificateCommand::Private::showErrorDialog(const KeyGenerationResult &result, const AuditLogEntry &auditLog)
{
    QString text;
    if (result.error() || !result.fingerprint()) {
        text = xi18nc("@info",
                      "<para>The creation of a new OpenPGP certificate failed.</para>"
                      "<para>Error: <message>%1</message></para>",
                      Formatting::errorAsString(result.error()));
    } else {
        // no error and we have a fingerprint, but there was no corresponding key in the key ring
        text = xi18nc("@info",
                      "<para>A new OpenPGP certificate was created successfully, but it has not been found in the key ring.</para>"
                      "<para>Fingerprint of the new certificate:<nl/>%1</para>",
                      Formatting::prettyID(result.fingerprint()));
    }

    auto dialog = MessageBox::create(parentWidgetOrView(),
                                     QDialogButtonBox::Retry | QDialogButtonBox::Ok,
                                     QMessageBox::Critical,
                                     text,
                                     auditLog,
                                     i18nc("@title:window", "Error"));
    connect(dialog, &QDialog::finished, q, [this](int buttonCode) {
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
    });
}

NewOpenPGPCertificateCommand::NewOpenPGPCertificateCommand()
    : NewOpenPGPCertificateCommand(nullptr, nullptr)
{
}

NewOpenPGPCertificateCommand::NewOpenPGPCertificateCommand(QAbstractItemView *v, KeyListController *c)
    : Command(v, new Private(this, c))
{
}

NewOpenPGPCertificateCommand::~NewOpenPGPCertificateCommand() = default;

void NewOpenPGPCertificateCommand::doStart()
{
    d->getCertificateDetails();
}

void NewOpenPGPCertificateCommand::doCancel()
{
    if (d->detailsDialog) {
        d->detailsDialog->close();
    }
    if (d->job) {
        d->job->slotCancel();
    }
}

#undef d
#undef q

#include "moc_newopenpgpcertificatecommand.cpp"
