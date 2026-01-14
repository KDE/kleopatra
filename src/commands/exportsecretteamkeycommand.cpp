// SPDX-FileCopyrightText: 2025 g10 Code GmbH
// SPDX-FileContributor: Tobias Fella <tobias.fella@gnupg.com>
// SPDX-License-Identifier: LGPL-2.0-or-later

#include <config-kleopatra.h>

#include "exportsecretteamkeycommand.h"

#include "command_p.h"

#include <utils/applicationstate.h>
#include <utils/filedialog.h>
#include <utils/path-helper.h>

#include <settings.h>

#include <Libkleo/AuditLogEntry>
#include <Libkleo/Classify>
#include <Libkleo/Formatting>

#include <KLocalizedString>
#include <KSharedConfig>

#include <QGpgME/Debug>
#include <QGpgME/ExportJob>
#include <QGpgME/Protocol>

#include <QCheckBox>
#include <QDialog>
#include <QFileInfo>
#include <QLabel>
#include <QPushButton>
#include <QStandardPaths>
#include <QVBoxLayout>

#include <gpgme++/context.h>

#include <gpgme.h>
#include <qgpgme/qgpgme_version.h>

#include <memory>
#include <span>

#include <kleopatra_debug.h>

using namespace Kleo;
using namespace Kleo::Commands;
using namespace GpgME;
using namespace Qt::Literals::StringLiterals;

static QString openPGPCertificateFileExtension()
{
    return outputFileExtension(Class::OpenPGP | Class::Ascii | Class::Certificate, Settings().usePGPFileExt());
}

static QString proposeFilename(const Key &key, bool exportSecretSigningSubkey)
{
    const QString name = Kleo::sanitizedFileName(Formatting::prettyNameOrEMail(key));
    const auto keyID = Formatting::prettyKeyID(key.keyID());
    /* Not translated so it's better to use in tutorials etc. */
    const QString filename = (exportSecretSigningSubkey //
                                  ? QStringView{u"%1_%2_SECRET_TEAM_KEY_ENCRYPT_SIGN"}.arg(name, keyID)
                                  : QStringView{u"%1_%2_SECRET_TEAM_KEY_ENCRYPT"}.arg(name, keyID));

    return ApplicationState::lastUsedExportDirectory() + u'/' + filename + u'.' + openPGPCertificateFileExtension();
}

static QString requestFilename(const QString &proposedFilename, QWidget *parent)
{
    auto filename = FileDialog::getSaveFileNameEx(parent,
                                                  i18nc("@title:window", "Save Secret Team Key"),
                                                  QStringLiteral("imp"),
                                                  proposedFilename,
                                                  i18nc("description of filename filter", "Secret Key Files") + QLatin1StringView{" (*.asc *.gpg *.pgp)"});

    if (!filename.isEmpty()) {
        const QFileInfo fi{filename};
        if (fi.suffix().isEmpty()) {
            filename += u'.' + openPGPCertificateFileExtension();
        }
        ApplicationState::setLastUsedExportDirectory(filename);
    }

    return filename;
}

class ExportSecretTeamKeyCommand::Private : public Command::Private
{
    friend class ::ExportSecretTeamKeyCommand;
    ExportSecretTeamKeyCommand *q_func() const
    {
        return static_cast<ExportSecretTeamKeyCommand *>(q);
    }

public:
    explicit Private(ExportSecretTeamKeyCommand *qq, KeyListController *c = nullptr);
    ~Private() override;

    void start();
    void cancel();

private:
    enum class OutputFormat {
        Binary,
        Armor
    };

    std::unique_ptr<QGpgME::ExportJob> startExportJob(const QStringList &fingerprints, OutputFormat format);
    void onExportJobResult(const Error &err, const QByteArray &keyData, const AuditLogEntry &auditLog);
    void showError(const Error &err, const AuditLogEntry &auditLog = {});
    void prepareExport(bool exportSecretSigningSubkey);

private:
    QString filename;
    QByteArray publicSigningKeyData;
    QPointer<QGpgME::ExportJob> job;
};

ExportSecretTeamKeyCommand::Private *ExportSecretTeamKeyCommand::d_func()
{
    return static_cast<Private *>(d.get());
}
const ExportSecretTeamKeyCommand::Private *ExportSecretTeamKeyCommand::d_func() const
{
    return static_cast<const Private *>(d.get());
}

#define d d_func()
#define q q_func()

ExportSecretTeamKeyCommand::Private::Private(ExportSecretTeamKeyCommand *qq, KeyListController *c)
    : Command::Private{qq, c}
{
}

ExportSecretTeamKeyCommand::Private::~Private() = default;

void ExportSecretTeamKeyCommand::Private::start()
{
    if (key().isNull()) {
        finished();
        return;
    }

    auto dialog = new QDialog(parentWidgetOrView());
    dialog->setAttribute(Qt::WA_DeleteOnClose);
    dialog->setWindowTitle(i18nc("@title:dialog", "Save Secret Team Key"));

    auto layout = new QVBoxLayout(dialog);

    auto label = new QLabel(i18nc("@info", "After importing the team key, team members will be able to decrypt data with it."));
    layout->addWidget(label);
    auto signLabel = new QLabel(i18nc("@info",
                                      "Please choose whether members should also be allowed to sign data with the team key.\n"
                                      "Alternatively, they can use their personal key for signing."));

    const auto subkeys = key().subkeys();
    auto hasSecretSigningSubkey = std::ranges::any_of(std::span{subkeys}.subspan(1), [](const auto &subkey) {
        return subkey.canSign() && !subkey.isBad() && subkey.isSecret();
    });
    signLabel->setVisible(hasSecretSigningSubkey);
    layout->addWidget(signLabel);

    auto signCheckbox = new QCheckBox(i18nc("@option:check", "Allow team members to sign with the team key"));
    signCheckbox->setVisible(hasSecretSigningSubkey);

    signCheckbox->setEnabled(hasSecretSigningSubkey);
    layout->addWidget(signCheckbox);

    auto noteLabel = new QLabel(i18nc("@info", "Team members will not be able to change the name, email address, or expiration date of the team key."));
    layout->addWidget(noteLabel);

    layout->addStretch();

    auto buttonBox = new QDialogButtonBox;

    auto saveButton = buttonBox->addButton(QDialogButtonBox::Save);
    connect(saveButton, &QPushButton::clicked, q, [dialog, this, signCheckbox]() {
        dialog->accept();
        prepareExport(signCheckbox->isChecked());
    });

    auto cancelButton = buttonBox->addButton(QDialogButtonBox::Cancel);
    connect(cancelButton, &QPushButton::clicked, q, [dialog, this]() {
        dialog->reject();
        q->cancel();
    });

    layout->addWidget(buttonBox);

    dialog->open();
}

void ExportSecretTeamKeyCommand::Private::cancel()
{
    if (job) {
        job->slotCancel();
    }
    job.clear();
}

std::unique_ptr<QGpgME::ExportJob> ExportSecretTeamKeyCommand::Private::startExportJob(const QStringList &fingerprints, OutputFormat format)
{
    std::unique_ptr<QGpgME::ExportJob> exportJob{QGpgME::openpgp()->secretSubkeyExportJob(format == OutputFormat::Armor)};
    Q_ASSERT(exportJob);

    connect(exportJob.get(), &QGpgME::ExportJob::result, q, [this](const auto &err, const auto &keyData, const auto auditLogAsHtml, const auto &auditLogError) {
        onExportJobResult(err, keyData, AuditLogEntry{auditLogAsHtml, auditLogError});
    });
    connect(exportJob.get(), &QGpgME::Job::jobProgress, q, &Command::progress);

    const auto err = exportJob->start(fingerprints);
    if (err) {
        showError(err);
        return {};
    }
    Q_EMIT q->info(i18nc("@info:status", "Saving secret team key..."));

    return exportJob;
}

void ExportSecretTeamKeyCommand::Private::onExportJobResult(const Error &err, const QByteArray &keyData, const AuditLogEntry &auditLog)
{
    if (err.isCanceled()) {
        finished();
        return;
    }

    if (err) {
        showError(err, auditLog);
        finished();
        return;
    }

    if (keyData.isEmpty()) {
        error(i18nc("@info", "The result is empty. Maybe you entered an empty or a wrong passphrase."));
        finished();
        return;
    }

    QFile f{filename};
    if (!f.open(QIODevice::WriteOnly)) {
        error(xi18nc("@info", "Cannot open file <filename>%1</filename> for writing.", filename));
        finished();
        return;
    }

    if (!publicSigningKeyData.isEmpty()) {
        const auto bytesWritten = f.write(publicSigningKeyData);
        if (bytesWritten != publicSigningKeyData.size()) {
            error(xi18nc("@info", "Writing key to file <filename>%1</filename> failed.", filename));
            finished();
            return;
        }
    }
    const auto bytesWritten = f.write(keyData);
    if (bytesWritten != keyData.size()) {
        error(xi18nc("@info", "Writing key to file <filename>%1</filename> failed.", filename));
        finished();
        return;
    }

    information(xi18nc("@info", "The secret team key was saved to <filename>%1</filename>", filename), i18nc("@title:window", "Save Secret Team Key"));

    finished();
}

void ExportSecretTeamKeyCommand::Private::showError(const Error &err, const AuditLogEntry &auditLog)
{
    error(xi18nc("@info",
                 "<para>An error occurred during the saving of the secret team key:</para>"
                 "<para><message>%1</message></para>",
                 Formatting::errorAsString(err)),
          auditLog);
}

ExportSecretTeamKeyCommand::ExportSecretTeamKeyCommand(QAbstractItemView *view, KeyListController *controller)
    : Command{view, new Private{this, controller}}
{
}

ExportSecretTeamKeyCommand::ExportSecretTeamKeyCommand(const GpgME::Key &key)
    : Command{key, new Private{this}}
{
}

ExportSecretTeamKeyCommand::~ExportSecretTeamKeyCommand() = default;

void ExportSecretTeamKeyCommand::doStart()
{
    d->start();
}

void ExportSecretTeamKeyCommand::doCancel()
{
    d->cancel();
}

void ExportSecretTeamKeyCommand::Private::prepareExport(bool exportSecretSigningSubkey)
{
    const Key key = this->key();

    filename = requestFilename(proposeFilename(key, exportSecretSigningSubkey), parentWidgetOrView());
    if (filename.isEmpty()) {
        canceled();
        return;
    }

    const OutputFormat format = filename.endsWith(".asc"_L1, Qt::CaseInsensitive) ? OutputFormat::Armor : OutputFormat::Binary;

    auto subkeys = key.subkeys();
    std::sort(subkeys.begin(), subkeys.end(), [](const auto left, const auto right) {
        return left.creationTime() > right.creationTime();
    });
    QString encryptKeyFpr;
    QString signKeyFpr;
    for (const auto &subkey : subkeys) {
        if (subkey.canCertify()) {
            // skip the primary key
            continue;
        }
        if (!subkey.isSecret()) {
            continue;
        }
        if (subkey.isBad()) {
            continue;
        }
        if (subkey.canSign()) {
            if (signKeyFpr.isEmpty()) {
                signKeyFpr = QString::fromLatin1(subkey.fingerprint());
            }
            continue;
        }
        if (subkey.canEncrypt()) {
            if (encryptKeyFpr.isEmpty()) {
                encryptKeyFpr = QString::fromLatin1(subkey.fingerprint());
            }
        }
    }
    QStringList fingerprints;
    fingerprints.append(encryptKeyFpr + u'!');
    if (exportSecretSigningSubkey && !signKeyFpr.isEmpty()) {
        fingerprints.append(signKeyFpr + u'!');
    }

    if (!exportSecretSigningSubkey && !signKeyFpr.isEmpty()) {
        // export the public signing subkey to share it together with the secret encryption subkey with the team members
        std::unique_ptr<QGpgME::ExportJob> exportJob{QGpgME::openpgp()->publicKeyExportJob(format == OutputFormat::Armor)};
#if GPGME_VERSION_NUMBER >= QT_VERSION_CHECK(2, 0, 2) && QGPGME_VERSION >= QT_VERSION_CHECK(2, 0, 1)
        // export only the signing subkey (if gpgme is new enough); otherwise, the complete public team key is exported
        exportJob->setExportFilter("drop-subkey=fpr <> "_L1 + signKeyFpr);
#endif
        // we use a blocking export because this should be fast
        Error err = exportJob->exec({QString::fromLatin1(key.primaryFingerprint())}, publicSigningKeyData);
        if (err) {
            qCWarning(KLEOPATRA_LOG) << "ExportSecretTeamKeyCommand: Failed to export the public signing key:" << err;
            publicSigningKeyData.clear(); // clear the export result just in case there's some garbage
            // a failed public key export shouldn't fail the command
        }
    }

    auto exportJob = startExportJob(fingerprints, format);
    if (!exportJob) {
        finished();
        return;
    }
    job = exportJob.release();
}

#undef d
#undef q

#include "moc_exportsecretteamkeycommand.cpp"
