/*
    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2008 Klarälvdalens Datakonsult AB

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include <config-kleopatra.h>

#include "decryptverifytask.h"

#include <QGpgME/DecryptJob>
#include <QGpgME/DecryptVerifyArchiveJob>
#include <QGpgME/DecryptVerifyJob>
#include <QGpgME/Protocol>
#include <QGpgME/VerifyDetachedJob>
#include <QGpgME/VerifyOpaqueJob>

#include <Libkleo/AuditLogEntry>
#include <Libkleo/Classify>
#include <Libkleo/Compliance>
#include <Libkleo/Dn>
#include <Libkleo/Formatting>
#include <Libkleo/KeyCache>
#include <Libkleo/KleoException>
#include <Libkleo/Predicates>
#include <Libkleo/Stl_Util>

#include <Libkleo/GnuPG>
#include <utils/detail_p.h>
#include <utils/input.h>
#include <utils/kleo_assert.h>
#include <utils/output.h>

#include <KEmailAddress>
#include <KMime/Types>

#include <gpgme++/context.h>
#include <gpgme++/decryptionresult.h>
#include <gpgme++/error.h>
#include <gpgme++/key.h>
#include <gpgme++/verificationresult.h>

#include <gpg-error.h>

#include "kleopatra_debug.h"

#include <KFileUtils>
#include <KLocalizedString>

#include <QByteArray>
#include <QDateTime>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QIODevice>
#include <QLocale>
#include <QMimeDatabase>
#include <QStringList>

#include <algorithm>
#include <sstream>

using namespace Kleo::Crypto;
using namespace Kleo;
using namespace GpgME;
using namespace KMime::Types;
using namespace Qt::Literals::StringLiterals;

using namespace Qt::Literals::StringLiterals;

namespace
{

static AuditLogEntry auditLogFromSender(QObject *sender)
{
    return AuditLogEntry::fromJob(qobject_cast<const QGpgME::Job *>(sender));
}

static std::vector<QString> extractEmails(const Key &key)
{
    std::vector<QString> res;
    const auto userIDs{key.userIDs()};
    for (const UserID &id : userIDs) {
        const auto email = Kleo::Formatting::email(id);
        if (!email.isEmpty()) {
            res.push_back(email);
        }
    }
    return res;
}

static bool keyContainsEmail(const Key &key, const QString &email)
{
    return std::ranges::any_of(extractEmails(key), [email](const QString &emailItem) {
        return emailItem.compare(email, Qt::CaseInsensitive) == 0;
    });
}

static void updateKeys(const VerificationResult &result)
{
    // This little hack works around the problem that GnuPG / GpgME does not
    // provide Key information in a verification result. The Key object is
    // a dummy just holding the KeyID. This hack ensures that all available
    // keys are fetched from the backend and are populated
    for (const auto &sig : result.signatures()) {
        // Update key information
        sig.key(true, true);
    }
}

static QString ensureUniqueDirectory(const QString &path)
{
    // make sure that we don't use an existing directory
    QString uniquePath = path;
    const QFileInfo outputInfo{path};
    if (outputInfo.exists()) {
        const auto uniqueName = KFileUtils::suggestName(QUrl::fromLocalFile(outputInfo.absolutePath()), outputInfo.fileName());
        uniquePath = outputInfo.dir().filePath(uniqueName);
    }
    if (!QDir{}.mkpath(uniquePath)) {
        return {};
    }
    return uniquePath;
}

static bool mimeTypeInherits(const QMimeType &mimeType, const QString &mimeTypeName)
{
    // inherits is expensive on an invalid mimeType
    return mimeType.isValid() && mimeType.inherits(mimeTypeName);
}
}

namespace
{

static QString formatRecipientsDetails(const std::vector<Key> &knownRecipients, unsigned int numRecipients)
{
    if (numRecipients == 0) {
        return {};
    }

    QString details = i18np("Recipient:", "Recipients:", numRecipients);

    if (numRecipients == 1) {
        if (knownRecipients.empty()) {
            details += QLatin1Char(' ') + i18nc("@info", "One unknown recipient");
        } else {
            details += QLatin1Char(' ') + Formatting::summaryLine(knownRecipients.front()).toHtmlEscaped();
        }
    } else {
        details += QLatin1StringView("<ul>");
        for (const Key &key : knownRecipients) {
            details += QLatin1StringView("<li>") + Formatting::summaryLine(key).toHtmlEscaped() + QLatin1StringView("</li>");
        }
        if (knownRecipients.size() < numRecipients) {
            details += QLatin1StringView("<li>") + i18np("One unknown recipient", "%1 unknown recipients", numRecipients - knownRecipients.size())
                + QLatin1StringView("</li>");
        }
        details += QLatin1StringView("</ul>");
    }

    return details;
}

} // anon namespace

class DecryptVerifyResult::Private
{
    DecryptVerifyResult *const q;

public:
    Private(const VerificationResult &vr,
            const DecryptionResult &dr,
            const QByteArray &stuff,
            const QString &fileName,
            const GpgME::Error &error,
            const QString &errString,
            const QString &input,
            const QString &output,
            const AuditLogEntry &auditLog,
            Task *parentTask,
            const Mailbox &informativeSender,
            Task::DataSource dataSource,
            DecryptVerifyResult *qq)
        : q(qq)
        , m_verificationResult(vr)
        , m_decryptionResult(dr)
        , m_stuff(stuff)
        , m_fileName(fileName)
        , m_error(error)
        , m_errorString(errString)
        , m_inputLabel(input)
        , m_outputLabel(output)
        , m_auditLog(auditLog)
        , m_parentTask(QPointer<Task>(parentTask))
        , m_informativeSender(informativeSender)
    {
        q->setDataSource(dataSource);
    }

    QString label() const
    {
        const auto verify = m_verificationResult.numSignatures() > 0;
        const auto decrypt = !m_decryptionResult.isNull();
        const auto recipients = KeyCache::instance()->findRecipients(m_decryptionResult);

        Q_ASSERT(verify || decrypt);

        Error error;
        if (m_error.code()) {
            error = m_error;
        } else if (m_decryptionResult.error().code()) {
            error = m_decryptionResult.error();
        } else {
            error = m_verificationResult.error();
        }

        QString label;
        if (verify && decrypt) {
            if (error.isCanceled()) {
                return i18nc("@info", "Decryption and verification of <filename>%1</filename> canceled.", m_inputLabel);
            } else if (error.code() == GPG_ERR_NO_SECKEY) {
                label = xi18nc("@info 'Unable' meaning that decryption can't be started because there is no secret key",
                               "Unable to decrypt and verify <filename>%1</filename>:",
                               m_inputLabel);
            } else if (error.code() != GPG_ERR_NO_ERROR) {
                label = xi18nc("@info 'Failed' meaning that there was an error during decryption",
                               "Failed to decrypt and verify <filename>%1</filename>:",
                               m_inputLabel);
            } else {
                label = xi18nc("@info Successfully decrypted and verified <file> as <file>.",
                               "Successfully decrypted and verified <filename>%1</filename> as <filename>%2</filename>.",
                               m_inputLabel,
                               m_outputLabel);
            }
        } else if (verify) {
            if (error.isCanceled()) {
                return i18nc("@info", "Verification of <filename>%1</filename> canceled.", m_inputLabel);
            } else if (error) {
                label = xi18nc("@info Failed to verify <file>:", "Failed to verify <filename>%1</filename>:", m_inputLabel);
            } else {
                label = xi18nc("@info Verified <file> with signature in <file>.",
                               "Verified <filename>%1</filename> with signature in <filename>%2</filename>.",
                               m_outputLabel,
                               m_inputLabel);
            }
        } else {
            if (error.isCanceled()) {
                return i18nc("@info", "Decryption of <filename>%1</filename> canceled.", m_inputLabel);
            } else if (error.code() == GPG_ERR_NO_SECKEY) {
                label = xi18nc("@info 'Unable' meaning that decryption can't be started because there is no secret key",
                               "Unable to decrypt <filename>%1</filename>:",
                               m_inputLabel);
            } else if (error.code() != GPG_ERR_NO_ERROR) {
                label = xi18nc("@info 'Failed' meaning that there was an error during decryption", "Failed to decrypt <filename>%1</filename>:", m_inputLabel);
            } else {
                label = xi18nc("@info Successfully decrypted <file> as <file>.",
                               "Successfully decrypted <filename>%1</filename> as <filename>%2</filename>.",
                               m_inputLabel,
                               m_outputLabel);
            }
        }

        if (error) {
            label += u' ' + Formatting::errorAsString(error) + u'.';
            if (error.code() == GPG_ERR_NO_SECKEY) {
                label += "<br />"_L1
                    + i18nc("@info",
                            "The data was not encrypted for any "
                            "secret key in your certificate list.");
            }
        } else if (m_decryptionResult.isLegacyCipherNoMDC()) {
            label += u' ' + i18n("No integrity protection (MDC).");
        } else if (!m_errorString.isEmpty()) {
            if (error.code()) {
                label += u' ' + Formatting::errorAsString(error) + ": "_L1;
            }
            label += m_errorString.toHtmlEscaped();
        }

        if (error) {
            return label;
        }

        if (DeVSCompliance::isCompliant()) {
            label += "<br />"_L1
                + ((m_decryptionResult.isDeVs()
                        ? i18nc("%1 is a placeholder for the name of a compliance mode. E.g. NATO RESTRICTED compliant or VS-NfD compliant",
                                "The decryption is %1.",
                                DeVSCompliance::name(true))
                        : i18nc("%1 is a placeholder for the name of a compliance mode. E.g. NATO RESTRICTED compliant or VS-NfD compliant",
                                "The decryption <b>is not</b> %1.",
                                DeVSCompliance::name(true))));
        }

        if (m_decryptionResult.fileName()) {
            const auto decVerifyTask = qobject_cast<AbstractDecryptVerifyTask *>(m_parentTask.data());
            if (decVerifyTask) {
                const auto embedFileName = QString::fromUtf8(m_decryptionResult.fileName()).toHtmlEscaped();

                if (embedFileName != decVerifyTask->outputLabel()) {
                    label += "<br />"_L1 + i18n("Embedded file name: '%1'", embedFileName);
                }
            }
        }

        if (!verify) {
            label += "<br/>"_L1 + i18n("<b>Note:</b> You cannot be sure who encrypted this message as it is not signed.");
        }

        if (m_decryptionResult.isLegacyCipherNoMDC()) {
            label += "<br />"_L1
                + i18nc("Integrity protection was missing because an old cipher was used.",
                        "<b>Hint:</b> If this file was encrypted before the year 2003 it is "
                        "likely that the file is legitimate.  This is because back "
                        "then integrity protection was not widely used.")
                + QStringLiteral("<br/><br/>")
                + i18nc("The user is offered to force decrypt a non integrity protected message. With the strong advice to re-encrypt it.",
                        "If you are confident that the file was not manipulated you should re-encrypt it after you have forced the decryption.")
                + QStringLiteral("<br/><br/>");
        }

        if (decrypt) {
            label += "<br/>"_L1 + formatRecipientsDetails(recipients, m_decryptionResult.numRecipients());
        }

        return label;
    }

    VerificationResult m_verificationResult;
    DecryptionResult m_decryptionResult;
    QByteArray m_stuff;
    QString m_fileName;
    GpgME::Error m_error;
    QString m_errorString;
    QString m_inputLabel;
    QString m_outputLabel;
    const AuditLogEntry m_auditLog;
    QPointer<Task> m_parentTask;
    const Mailbox m_informativeSender;
};

std::shared_ptr<DecryptVerifyResult>
AbstractDecryptVerifyTask::fromDecryptResult(const DecryptionResult &dr, const QByteArray &plaintext, const AuditLogEntry &auditLog)
{
    return std::shared_ptr<DecryptVerifyResult>(new DecryptVerifyResult(VerificationResult(), //
                                                                        dr,
                                                                        plaintext,
                                                                        {},
                                                                        {},
                                                                        QString(),
                                                                        inputLabel(),
                                                                        outputLabel(),
                                                                        auditLog,
                                                                        this,
                                                                        informativeSender(),
                                                                        dataSource()));
}

std::shared_ptr<DecryptVerifyResult> AbstractDecryptVerifyTask::fromDecryptResult(const GpgME::Error &err, const QString &what, const AuditLogEntry &auditLog)
{
    return std::shared_ptr<DecryptVerifyResult>(new DecryptVerifyResult(VerificationResult(), //
                                                                        DecryptionResult(err),
                                                                        QByteArray(),
                                                                        {},
                                                                        err,
                                                                        what,
                                                                        inputLabel(),
                                                                        outputLabel(),
                                                                        auditLog,
                                                                        this,
                                                                        informativeSender(),
                                                                        dataSource()));
}

std::shared_ptr<DecryptVerifyResult> AbstractDecryptVerifyTask::fromDecryptVerifyResult(const DecryptionResult &dr,
                                                                                        const VerificationResult &vr,
                                                                                        const QByteArray &plaintext,
                                                                                        const QString &fileName,
                                                                                        const AuditLogEntry &auditLog)
{
    const auto err = dr.error().code() ? dr.error() : vr.error();
    return std::shared_ptr<DecryptVerifyResult>(new DecryptVerifyResult(vr, //
                                                                        dr,
                                                                        plaintext,
                                                                        fileName,
                                                                        err,
                                                                        QString(),
                                                                        inputLabel(),
                                                                        outputLabel(),
                                                                        auditLog,
                                                                        this,
                                                                        informativeSender(),
                                                                        dataSource()));
}

std::shared_ptr<DecryptVerifyResult>
AbstractDecryptVerifyTask::fromDecryptVerifyResult(const GpgME::Error &err, const QString &details, const AuditLogEntry &auditLog)
{
    return std::shared_ptr<DecryptVerifyResult>(new DecryptVerifyResult(VerificationResult(), //
                                                                        DecryptionResult(err),
                                                                        QByteArray(),
                                                                        {},
                                                                        err,
                                                                        details,
                                                                        inputLabel(),
                                                                        outputLabel(),
                                                                        auditLog,
                                                                        this,
                                                                        informativeSender(),
                                                                        dataSource()));
}

std::shared_ptr<DecryptVerifyResult>
AbstractDecryptVerifyTask::fromVerifyOpaqueResult(const VerificationResult &vr, const QByteArray &plaintext, const AuditLogEntry &auditLog)
{
    return std::shared_ptr<DecryptVerifyResult>(new DecryptVerifyResult(vr, //
                                                                        DecryptionResult(),
                                                                        plaintext,
                                                                        {},
                                                                        {},
                                                                        QString(),
                                                                        inputLabel(),
                                                                        outputLabel(),
                                                                        auditLog,
                                                                        this,
                                                                        informativeSender(),
                                                                        dataSource()));
}
std::shared_ptr<DecryptVerifyResult>
AbstractDecryptVerifyTask::fromVerifyOpaqueResult(const GpgME::Error &err, const QString &details, const AuditLogEntry &auditLog)
{
    return std::shared_ptr<DecryptVerifyResult>(new DecryptVerifyResult(VerificationResult(err), //
                                                                        DecryptionResult(),
                                                                        QByteArray(),
                                                                        {},
                                                                        err,
                                                                        details,
                                                                        inputLabel(),
                                                                        outputLabel(),
                                                                        auditLog,
                                                                        this,
                                                                        informativeSender(),
                                                                        dataSource()));
}

std::shared_ptr<DecryptVerifyResult> AbstractDecryptVerifyTask::fromVerifyDetachedResult(const VerificationResult &vr, const AuditLogEntry &auditLog)
{
    return std::shared_ptr<DecryptVerifyResult>(new DecryptVerifyResult(vr, //
                                                                        DecryptionResult(),
                                                                        QByteArray(),
                                                                        {},
                                                                        {},
                                                                        QString(),
                                                                        inputLabel(),
                                                                        outputLabel(),
                                                                        auditLog,
                                                                        this,
                                                                        informativeSender(),
                                                                        dataSource()));
}
std::shared_ptr<DecryptVerifyResult>
AbstractDecryptVerifyTask::fromVerifyDetachedResult(const GpgME::Error &err, const QString &details, const AuditLogEntry &auditLog)
{
    return std::shared_ptr<DecryptVerifyResult>(new DecryptVerifyResult(VerificationResult(err), //
                                                                        DecryptionResult(),
                                                                        QByteArray(),
                                                                        {},
                                                                        err,
                                                                        details,
                                                                        inputLabel(),
                                                                        outputLabel(),
                                                                        auditLog,
                                                                        this,
                                                                        informativeSender(),
                                                                        dataSource()));
}

DecryptVerifyResult::DecryptVerifyResult(const VerificationResult &vr,
                                         const DecryptionResult &dr,
                                         const QByteArray &stuff,
                                         const QString &fileName,
                                         const GpgME::Error &error,
                                         const QString &errString,
                                         const QString &inputLabel,
                                         const QString &outputLabel,
                                         const AuditLogEntry &auditLog,
                                         Task *parentTask,
                                         const Mailbox &informativeSender,
                                         Task::DataSource dataSource)
    : Task::Result()
    , d(new Private(vr, dr, stuff, fileName, error, errString, inputLabel, outputLabel, auditLog, parentTask, informativeSender, dataSource, this))
{
}

Task::Result::ContentType DecryptVerifyResult::viewableContentType() const
{
    if (decryptionResult().isMime()) {
        return Task::Result::ContentType::Mime;
    }

    if (fileName().isEmpty()) {
        return Task::Result::ContentType::None;
    }

    if (fileName().endsWith(QStringLiteral("openpgp-encrypted-message"))) {
        return Task::Result::ContentType::Mime;
    }

    QMimeDatabase mimeDatabase;
    const auto mimeType = mimeDatabase.mimeTypeForFile(fileName());
    if (mimeTypeInherits(mimeType, QStringLiteral("message/rfc822"))) {
        return Task::Result::ContentType::Mime;
    }

    if (mimeTypeInherits(mimeType, QStringLiteral("application/mbox"))) {
        return Task::Result::ContentType::Mbox;
    }

    return Task::Result::ContentType::None;
}

QString DecryptVerifyResult::details() const
{
    return {};
}

QString DecryptVerifyResult::overview() const
{
    const auto decrypting = !d->m_decryptionResult.isNull();
    const auto verifying = d->m_verificationResult.numSignatures() > 0;

    if (dataSource() == Task::Notepad) {
        if (decrypting && d->m_decryptionResult.error()) {
            return i18nc("@info", "Failed to decrypt the notepad: %1", Formatting::errorAsString(d->m_decryptionResult.error()));
        }
        if (verifying && d->m_verificationResult.error()) {
            return i18nc("@info", "Failed to verify the notepad: %1", Formatting::errorAsString(d->m_verificationResult.error()));
        }

        if (decrypting && verifying) {
            return i18nc("@info", "Successfully decrypted and verified the notepad");
        }
        if (decrypting) {
            return i18nc("@info", "Successfully decrypted the notepad");
        }
        if (verifying) {
            return i18nc("@info", "Successfully verified the notepad");
        }
        return {};
    } else if (dataSource() == Task::Clipboard) {
        if (decrypting && d->m_decryptionResult.error()) {
            return i18nc("@info", "Failed to decrypt the clipboard: %1", Formatting::errorAsString(d->m_decryptionResult.error()));
        }
        if (verifying && d->m_verificationResult.error()) {
            return i18nc("@info", "Failed to verify the clipboard: %1", Formatting::errorAsString(d->m_verificationResult.error()));
        }

        if (decrypting && verifying) {
            return i18nc("@info", "Successfully decrypted and verified the clipboard");
        }
        if (decrypting) {
            return i18nc("@info", "Successfully decrypted the clipboard");
        }
        if (verifying) {
            return i18nc("@info", "Successfully verified the clipboard");
        }
        return {};
    }
    return d->label();
}

static Task::Result::VisualCode codeForSignature(const Signature &signature)
{
    if (signature.summary() & Signature::Red) {
        return Task::Result::VisualCode::Danger;
    }
    if ((signature.summary() & Signature::Valid) || (signature.summary() & Signature::Green)) {
        return Task::Result::AllGood;
    }
    return Task::Result::Warning;
}

QList<Task::Result::ResultListItem> DecryptVerifyResult::detailsList() const
{
    QList<Task::Result::ResultListItem> details;
    for (const Signature &sig : d->m_verificationResult.signatures()) {
        const auto signerKey = KeyCache::instance()->findSigner(sig);
        const auto informativeMailAddress = QString::fromUtf8(d->m_informativeSender.address());
        auto text = Kleo::Formatting::prettySignature(sig, informativeMailAddress);
        if (!informativeMailAddress.isEmpty() && !signerKey.isNull() && !keyContainsEmail(signerKey, informativeMailAddress)) {
            QString emailsList;
            for (const auto &email : extractEmails(signerKey)) {
                emailsList += "<li>"_L1 + email + "</li>"_L1;
            }
            text += "<br />"_L1
                + i18nc("@info",
                        "Warning: The sender's mail address is not stored in the <a href=\"key:%1\">certificate</a> used for signing. Stored:<ul>%2</ul>",
                        QString::fromLatin1(sig.key().primaryFingerprint()),
                        emailsList);
        }
        details += Task::Result::ResultListItem{
            .details = text,
            .code = codeForSignature(sig),
        };
    }
    return details;
}

GpgME::Error DecryptVerifyResult::error() const
{
    return d->m_error;
}

QString DecryptVerifyResult::errorString() const
{
    return d->m_errorString;
}

AuditLogEntry DecryptVerifyResult::auditLog() const
{
    return d->m_auditLog;
}

QPointer<Task> DecryptVerifyResult::parentTask() const
{
    return d->m_parentTask;
}

GpgME::VerificationResult DecryptVerifyResult::verificationResult() const
{
    return d->m_verificationResult;
}

GpgME::DecryptionResult DecryptVerifyResult::decryptionResult() const
{
    return d->m_decryptionResult;
}

QString DecryptVerifyResult::fileName() const
{
    return d->m_fileName;
}

class AbstractDecryptVerifyTask::Private
{
public:
    Mailbox informativeSender;
    QPointer<QGpgME::Job> job;
    Task::DataSource dataSource = Task::Files;
};

AbstractDecryptVerifyTask::AbstractDecryptVerifyTask(QObject *parent)
    : Task(parent)
    , d(new Private)
{
}

AbstractDecryptVerifyTask::~AbstractDecryptVerifyTask()
{
}

void AbstractDecryptVerifyTask::cancel()
{
    qCDebug(KLEOPATRA_LOG) << this << __func__;
    if (d->job) {
        d->job->slotCancel();
    }
}

Mailbox AbstractDecryptVerifyTask::informativeSender() const
{
    return d->informativeSender;
}

void AbstractDecryptVerifyTask::setInformativeSender(const Mailbox &sender)
{
    d->informativeSender = sender;
}

QGpgME::Job *AbstractDecryptVerifyTask::job() const
{
    return d->job;
}

void AbstractDecryptVerifyTask::setJob(QGpgME::Job *job)
{
    d->job = job;
}

class DecryptVerifyTask::Private
{
    DecryptVerifyTask *const q;

public:
    explicit Private(DecryptVerifyTask *qq)
        : q{qq}
    {
    }

    void startDecryptVerifyJob();
    void startDecryptVerifyArchiveJob();

    void slotResult(const DecryptionResult &, const VerificationResult &, const QByteArray & = {});

    std::shared_ptr<Input> m_input;
    std::shared_ptr<Output> m_output;
    const QGpgME::Protocol *m_backend = nullptr;
    Protocol m_protocol = UnknownProtocol;
    bool m_ignoreMDCError = false;
    bool m_extractArchive = false;
    QString m_inputFilePath;
    QString m_outputFilePath;
    QString m_outputDirectory;
};

void DecryptVerifyTask::Private::slotResult(const DecryptionResult &dr, const VerificationResult &vr, const QByteArray &plainText)
{
    updateKeys(vr);
    {
        std::stringstream ss;
        ss << dr << '\n' << vr;
        qCDebug(KLEOPATRA_LOG) << ss.str().c_str();
    }
    const AuditLogEntry auditLog = auditLogFromSender(q->sender());
    if (m_output) {
        if (dr.error().code() || vr.error().code()) {
            m_output->cancel();
        } else {
            try {
                kleo_assert(!dr.isNull() || !vr.isNull());
                m_output->finalize();
            } catch (const GpgME::Exception &e) {
                q->emitResult(q->fromDecryptResult(e.error(), QString::fromLocal8Bit(e.what()), auditLog));
                return;
            } catch (const std::exception &e) {
                q->emitResult(
                    q->fromDecryptResult(Error::fromCode(GPG_ERR_INTERNAL), i18n("Caught exception: %1", QString::fromLocal8Bit(e.what())), auditLog));
                return;
            } catch (...) {
                q->emitResult(q->fromDecryptResult(Error::fromCode(GPG_ERR_INTERNAL), i18n("Caught unknown exception"), auditLog));
                return;
            }
        }
    }
    const int drErr = dr.error().code();
    const QString errorString = m_output ? m_output->errorString() : QString{};
    if (((drErr == GPG_ERR_EIO || drErr == GPG_ERR_NO_DATA) && !errorString.isEmpty()) || (m_output && m_output->failed())) {
        q->emitResult(q->fromDecryptResult(drErr ? dr.error() : Error::fromCode(GPG_ERR_EIO), errorString, auditLog));
        return;
    }

    q->emitResult(q->fromDecryptVerifyResult(dr, vr, plainText, m_output ? m_output->fileName() : m_outputFilePath, auditLog));
}

DecryptVerifyTask::DecryptVerifyTask(QObject *parent)
    : AbstractDecryptVerifyTask(parent)
    , d(new Private(this))
{
}

DecryptVerifyTask::~DecryptVerifyTask()
{
}

void DecryptVerifyTask::setInput(const std::shared_ptr<Input> &input)
{
    d->m_input = input;
    kleo_assert(d->m_input && d->m_input->ioDevice());
}

void DecryptVerifyTask::setOutput(const std::shared_ptr<Output> &output)
{
    d->m_output = output;
    kleo_assert(d->m_output && d->m_output->ioDevice());
}

void DecryptVerifyTask::setProtocol(Protocol prot)
{
    kleo_assert(prot != UnknownProtocol);
    d->m_protocol = prot;
    d->m_backend = prot == GpgME::OpenPGP ? QGpgME::openpgp() : QGpgME::smime();
    kleo_assert(d->m_backend);
}

void DecryptVerifyTask::autodetectProtocolFromInput()
{
    if (!d->m_input) {
        return;
    }
    const Protocol p = findProtocol(d->m_input->classification());
    if (p == UnknownProtocol) {
        throw Exception(
            gpg_error(GPG_ERR_NOTHING_FOUND),
            i18n("Could not determine whether this is an S/MIME or an OpenPGP signature/ciphertext - maybe it is neither ciphertext nor a signature?"),
            Exception::MessageOnly);
    }
    setProtocol(p);
}

QString DecryptVerifyTask::label() const
{
    return i18n("Decrypting %1...", inputLabel());
}

unsigned long long DecryptVerifyTask::inputSize() const
{
    return d->m_input ? d->m_input->size() : 0;
}

QString DecryptVerifyTask::inputLabel() const
{
    return d->m_input ? d->m_input->label() : QFileInfo{d->m_inputFilePath}.fileName();
}

QString DecryptVerifyTask::outputLabel() const
{
    if (d->m_output) {
        return d->m_output->label();
    } else if (!d->m_outputFilePath.isEmpty()) {
        return QFileInfo{d->m_outputFilePath}.fileName();
    } else {
        return d->m_outputDirectory;
    }
}

Protocol DecryptVerifyTask::protocol() const
{
    return d->m_protocol;
}

static void ensureIOOpen(QIODevice *input, QIODevice *output)
{
    if (input && !input->isOpen()) {
        input->open(QIODevice::ReadOnly);
    }
    if (output && !output->isOpen()) {
        output->open(QIODevice::WriteOnly);
    }
}

void DecryptVerifyTask::setIgnoreMDCError(bool value)
{
    d->m_ignoreMDCError = value;
}

void DecryptVerifyTask::setExtractArchive(bool extract)
{
    d->m_extractArchive = extract;
}

void DecryptVerifyTask::setInputFile(const QString &path)
{
    d->m_inputFilePath = path;
}

void DecryptVerifyTask::setOutputFile(const QString &path)
{
    d->m_outputFilePath = path;
}

void DecryptVerifyTask::setOutputDirectory(const QString &directory)
{
    d->m_outputDirectory = directory;
}

static bool archiveJobsCanBeUsed(GpgME::Protocol protocol)
{
    return (protocol == GpgME::OpenPGP) && QGpgME::DecryptVerifyArchiveJob::isSupported();
}

void DecryptVerifyTask::doStart()
{
    kleo_assert(d->m_backend);
    if (d->m_extractArchive && archiveJobsCanBeUsed(d->m_protocol)) {
        d->startDecryptVerifyArchiveJob();
    } else {
        d->startDecryptVerifyJob();
    }
}

static void setIgnoreMDCErrorFlag(QGpgME::Job *job, bool ignoreMDCError)
{
    if (ignoreMDCError) {
        qCDebug(KLEOPATRA_LOG) << "Modifying job to ignore MDC errors.";
        auto ctx = QGpgME::Job::context(job);
        if (!ctx) {
            qCWarning(KLEOPATRA_LOG) << "Failed to get context for job";
        } else {
            const auto err = ctx->setFlag("ignore-mdc-error", "1");
            if (err) {
                qCWarning(KLEOPATRA_LOG) << "Failed to set ignore mdc errors" << Formatting::errorAsString(err);
            }
        }
    }
}

void DecryptVerifyTask::Private::startDecryptVerifyJob()
{
#if QGPGME_FILE_JOBS_SUPPORT_DIRECT_FILE_IO
    if (!m_outputFilePath.isEmpty() && QFile::exists(m_outputFilePath)) {
        // The output files are always written to a temporary location. Therefore, this can only occur
        // if two signed/encrypted files with the same name in different folders are verified/decrypted
        // because they would be written to the same temporary location.
        QMetaObject::invokeMethod(
            q,
            [this]() {
                slotResult(DecryptionResult{Error::fromCode(GPG_ERR_EEXIST)}, VerificationResult{});
            },
            Qt::QueuedConnection);
        return;
    }
#endif
    try {
        std::unique_ptr<QGpgME::DecryptVerifyJob> job{m_backend->decryptVerifyJob()};
        kleo_assert(job);
        setIgnoreMDCErrorFlag(job.get(), m_ignoreMDCError);
        QObject::connect(job.get(),
                         &QGpgME::DecryptVerifyJob::result,
                         q,
                         [this](const GpgME::DecryptionResult &decryptResult, const GpgME::VerificationResult &verifyResult, const QByteArray &plainText) {
                             slotResult(decryptResult, verifyResult, plainText);
                         });
        connect(job.get(), &QGpgME::Job::jobProgress, q, &DecryptVerifyTask::setProgress);
#if QGPGME_SUPPORTS_PROCESS_ALL_SIGNATURES
        job->setProcessAllSignatures(true);
#endif
#if QGPGME_FILE_JOBS_SUPPORT_DIRECT_FILE_IO
        if (!m_inputFilePath.isEmpty() && !m_outputFilePath.isEmpty()) {
            job->setInputFile(m_inputFilePath);
            job->setOutputFile(m_outputFilePath);
            const auto err = job->startIt();
        } else {
            ensureIOOpen(m_input->ioDevice().get(), m_output->ioDevice().get());
            job->start(m_input->ioDevice(), m_output->ioDevice());
        }
#else
        ensureIOOpen(m_input->ioDevice().get(), m_output->ioDevice().get());
        job->start(m_input->ioDevice(), m_output->ioDevice());
#endif
        q->setJob(job.release());
    } catch (const GpgME::Exception &e) {
        q->emitResult(q->fromDecryptVerifyResult(e.error(), QString::fromLocal8Bit(e.what()), AuditLogEntry()));
    } catch (const std::exception &e) {
        q->emitResult(
            q->fromDecryptVerifyResult(Error::fromCode(GPG_ERR_INTERNAL), i18n("Caught exception: %1", QString::fromLocal8Bit(e.what())), AuditLogEntry()));
    } catch (...) {
        q->emitResult(q->fromDecryptVerifyResult(Error::fromCode(GPG_ERR_INTERNAL), i18n("Caught unknown exception"), AuditLogEntry()));
    }
}

void DecryptVerifyTask::Private::startDecryptVerifyArchiveJob()
{
    std::unique_ptr<QGpgME::DecryptVerifyArchiveJob> job{m_backend->decryptVerifyArchiveJob()};
    kleo_assert(job);
    setIgnoreMDCErrorFlag(job.get(), m_ignoreMDCError);
    connect(job.get(),
            &QGpgME::DecryptVerifyArchiveJob::result,
            q,
            [this](const GpgME::DecryptionResult &decryptResult, const GpgME::VerificationResult &verifyResult) {
                slotResult(decryptResult, verifyResult);
            });
    connect(job.get(), &QGpgME::Job::jobProgress, q, &DecryptVerifyTask::setProgress);
    // make sure that we don't use an existing output directory
    const auto outputDirectory = ensureUniqueDirectory(m_outputDirectory);
    if (outputDirectory.isEmpty()) {
        q->emitResult(q->fromDecryptVerifyResult(Error::fromCode(GPG_ERR_GENERAL), {}, {}));
        return;
    }
    m_outputDirectory = outputDirectory;
    m_outputFilePath = outputDirectory;
#if QGPGME_SUPPORTS_PROCESS_ALL_SIGNATURES
    job->setProcessAllSignatures(true);
#endif
    job->setInputFile(m_inputFilePath);
    job->setOutputDirectory(m_outputDirectory);
    const auto err = job->startIt();
    q->setJob(job.release());
    if (err) {
        q->emitResult(q->fromDecryptVerifyResult(err, {}, {}));
    }
}

class DecryptTask::Private
{
    DecryptTask *const q;

public:
    explicit Private(DecryptTask *qq)
        : q{qq}
    {
    }

    void slotResult(const DecryptionResult &, const QByteArray &);

    void registerJob(QGpgME::DecryptJob *job)
    {
        q->connect(job, SIGNAL(result(GpgME::DecryptionResult, QByteArray)), q, SLOT(slotResult(GpgME::DecryptionResult, QByteArray)));
        q->connect(job, &QGpgME::Job::jobProgress, q, &DecryptTask::setProgress);
    }

    std::shared_ptr<Input> m_input;
    std::shared_ptr<Output> m_output;
    const QGpgME::Protocol *m_backend = nullptr;
    Protocol m_protocol = UnknownProtocol;
};

void DecryptTask::Private::slotResult(const DecryptionResult &result, const QByteArray &plainText)
{
    {
        std::stringstream ss;
        ss << result;
        qCDebug(KLEOPATRA_LOG) << ss.str().c_str();
    }
    const AuditLogEntry auditLog = auditLogFromSender(q->sender());
    if (result.error().code()) {
        m_output->cancel();
    } else {
        try {
            kleo_assert(!result.isNull());
            m_output->finalize();
        } catch (const GpgME::Exception &e) {
            q->emitResult(q->fromDecryptResult(e.error(), QString::fromLocal8Bit(e.what()), auditLog));
            return;
        } catch (const std::exception &e) {
            q->emitResult(q->fromDecryptResult(Error::fromCode(GPG_ERR_INTERNAL), i18n("Caught exception: %1", QString::fromLocal8Bit(e.what())), auditLog));
            return;
        } catch (...) {
            q->emitResult(q->fromDecryptResult(Error::fromCode(GPG_ERR_INTERNAL), i18n("Caught unknown exception"), auditLog));
            return;
        }
    }

    const int drErr = result.error().code();
    const QString errorString = m_output->errorString();
    if (((drErr == GPG_ERR_EIO || drErr == GPG_ERR_NO_DATA) && !errorString.isEmpty()) || m_output->failed()) {
        q->emitResult(q->fromDecryptResult(result.error() ? result.error() : Error::fromCode(GPG_ERR_EIO), errorString, auditLog));
        return;
    }

    q->emitResult(q->fromDecryptResult(result, plainText, auditLog));
}

DecryptTask::DecryptTask(QObject *parent)
    : AbstractDecryptVerifyTask(parent)
    , d(new Private(this))
{
}

DecryptTask::~DecryptTask()
{
}

void DecryptTask::setInput(const std::shared_ptr<Input> &input)
{
    d->m_input = input;
    kleo_assert(d->m_input && d->m_input->ioDevice());
}

void DecryptTask::setOutput(const std::shared_ptr<Output> &output)
{
    d->m_output = output;
    kleo_assert(d->m_output && d->m_output->ioDevice());
}

void DecryptTask::setProtocol(Protocol prot)
{
    kleo_assert(prot != UnknownProtocol);
    d->m_protocol = prot;
    d->m_backend = (prot == GpgME::OpenPGP) ? QGpgME::openpgp() : QGpgME::smime();
    kleo_assert(d->m_backend);
}

void DecryptTask::autodetectProtocolFromInput()
{
    if (!d->m_input) {
        return;
    }
    const Protocol p = findProtocol(d->m_input->classification());
    if (p == UnknownProtocol) {
        throw Exception(gpg_error(GPG_ERR_NOTHING_FOUND),
                        i18n("Could not determine whether this was S/MIME- or OpenPGP-encrypted - maybe it is not ciphertext at all?"),
                        Exception::MessageOnly);
    }
    setProtocol(p);
}

QString DecryptTask::label() const
{
    return i18n("Decrypting: %1...", d->m_input->label());
}

unsigned long long DecryptTask::inputSize() const
{
    return d->m_input ? d->m_input->size() : 0;
}

QString DecryptTask::inputLabel() const
{
    return d->m_input ? d->m_input->label() : QString();
}

QString DecryptTask::outputLabel() const
{
    return d->m_output ? d->m_output->label() : QString();
}

Protocol DecryptTask::protocol() const
{
    return d->m_protocol;
}

void DecryptTask::doStart()
{
    kleo_assert(d->m_backend);

    try {
        std::unique_ptr<QGpgME::DecryptJob> job{d->m_backend->decryptJob()};
        kleo_assert(job);
        d->registerJob(job.get());
        ensureIOOpen(d->m_input->ioDevice().get(), d->m_output->ioDevice().get());
        job->start(d->m_input->ioDevice(), d->m_output->ioDevice());
        setJob(job.release());
    } catch (const GpgME::Exception &e) {
        emitResult(fromDecryptResult(e.error(), QString::fromLocal8Bit(e.what()), AuditLogEntry()));
    } catch (const std::exception &e) {
        emitResult(fromDecryptResult(Error::fromCode(GPG_ERR_INTERNAL), i18n("Caught exception: %1", QString::fromLocal8Bit(e.what())), AuditLogEntry()));
    } catch (...) {
        emitResult(fromDecryptResult(Error::fromCode(GPG_ERR_INTERNAL), i18n("Caught unknown exception"), AuditLogEntry()));
    }
}

class VerifyOpaqueTask::Private
{
    VerifyOpaqueTask *const q;

public:
    explicit Private(VerifyOpaqueTask *qq)
        : q{qq}
    {
    }

    void startVerifyOpaqueJob();
    void startDecryptVerifyArchiveJob();

    void slotResult(const VerificationResult &, const QByteArray & = {});

    std::shared_ptr<Input> m_input;
    std::shared_ptr<Output> m_output;
    const QGpgME::Protocol *m_backend = nullptr;
    Protocol m_protocol = UnknownProtocol;
    bool m_extractArchive = false;
    QString m_inputFilePath;
    QString m_outputFilePath;
    QString m_outputDirectory;
};

void VerifyOpaqueTask::Private::slotResult(const VerificationResult &result, const QByteArray &plainText)
{
    updateKeys(result);
    {
        std::stringstream ss;
        ss << result;
        qCDebug(KLEOPATRA_LOG) << ss.str().c_str();
    }
    const AuditLogEntry auditLog = auditLogFromSender(q->sender());
    if (m_output) {
        if (result.error().code()) {
            m_output->cancel();
        } else {
            try {
                kleo_assert(!result.isNull());
                m_output->finalize();
            } catch (const GpgME::Exception &e) {
                q->emitResult(q->fromVerifyOpaqueResult(e.error(), QString::fromLocal8Bit(e.what()), auditLog));
                return;
            } catch (const std::exception &e) {
                q->emitResult(
                    q->fromVerifyOpaqueResult(Error::fromCode(GPG_ERR_INTERNAL), i18n("Caught exception: %1", QString::fromLocal8Bit(e.what())), auditLog));
                return;
            } catch (...) {
                q->emitResult(q->fromVerifyOpaqueResult(Error::fromCode(GPG_ERR_INTERNAL), i18n("Caught unknown exception"), auditLog));
                return;
            }
        }
    }

    const int drErr = result.error().code();
    const QString errorString = m_output ? m_output->errorString() : QString{};
    if (((drErr == GPG_ERR_EIO || drErr == GPG_ERR_NO_DATA) && !errorString.isEmpty()) || (m_output && m_output->failed())) {
        q->emitResult(q->fromVerifyOpaqueResult(result.error() ? result.error() : Error::fromCode(GPG_ERR_EIO), errorString, auditLog));
        return;
    }

    q->emitResult(q->fromVerifyOpaqueResult(result, plainText, auditLog));
}

VerifyOpaqueTask::VerifyOpaqueTask(QObject *parent)
    : AbstractDecryptVerifyTask(parent)
    , d(new Private(this))
{
}

VerifyOpaqueTask::~VerifyOpaqueTask()
{
}

void VerifyOpaqueTask::setInput(const std::shared_ptr<Input> &input)
{
    d->m_input = input;
    kleo_assert(d->m_input && d->m_input->ioDevice());
}

void VerifyOpaqueTask::setOutput(const std::shared_ptr<Output> &output)
{
    d->m_output = output;
    kleo_assert(d->m_output && d->m_output->ioDevice());
}

void VerifyOpaqueTask::setProtocol(Protocol prot)
{
    kleo_assert(prot != UnknownProtocol);
    d->m_protocol = prot;
    d->m_backend = (prot == GpgME::OpenPGP) ? QGpgME::openpgp() : QGpgME::smime();
    kleo_assert(d->m_backend);
}

void VerifyOpaqueTask::autodetectProtocolFromInput()
{
    if (!d->m_input) {
        return;
    }
    const Protocol p = findProtocol(d->m_input->classification());
    if (p == UnknownProtocol) {
        throw Exception(gpg_error(GPG_ERR_NOTHING_FOUND),
                        i18n("Could not determine whether this is an S/MIME or an OpenPGP signature - maybe it is not a signature at all?"),
                        Exception::MessageOnly);
    }
    setProtocol(p);
}

QString VerifyOpaqueTask::label() const
{
    return i18n("Verifying %1...", inputLabel());
}

unsigned long long VerifyOpaqueTask::inputSize() const
{
    return d->m_input ? d->m_input->size() : 0;
}

QString VerifyOpaqueTask::inputLabel() const
{
    return d->m_input ? d->m_input->label() : QFileInfo{d->m_inputFilePath}.fileName();
}

QString VerifyOpaqueTask::outputLabel() const
{
    if (d->m_output) {
        return d->m_output->label();
    } else if (!d->m_outputFilePath.isEmpty()) {
        return QFileInfo{d->m_outputFilePath}.fileName();
    } else {
        return d->m_outputDirectory;
    }
}

Protocol VerifyOpaqueTask::protocol() const
{
    return d->m_protocol;
}

void VerifyOpaqueTask::setExtractArchive(bool extract)
{
    d->m_extractArchive = extract;
}

void VerifyOpaqueTask::setInputFile(const QString &path)
{
    d->m_inputFilePath = path;
}

void VerifyOpaqueTask::setOutputFile(const QString &path)
{
    d->m_outputFilePath = path;
}

void VerifyOpaqueTask::setOutputDirectory(const QString &directory)
{
    d->m_outputDirectory = directory;
}

void VerifyOpaqueTask::doStart()
{
    kleo_assert(d->m_backend);
    if (d->m_extractArchive && archiveJobsCanBeUsed(d->m_protocol)) {
        d->startDecryptVerifyArchiveJob();
    } else {
        d->startVerifyOpaqueJob();
    }
}

void VerifyOpaqueTask::Private::startVerifyOpaqueJob()
{
#if QGPGME_FILE_JOBS_SUPPORT_DIRECT_FILE_IO
    if (!m_outputFilePath.isEmpty() && QFile::exists(m_outputFilePath)) {
        // The output files are always written to a temporary location. Therefore, this can only occur
        // if two signed/encrypted files with the same name in different folders are verified/decrypted
        // because they would be written to the same temporary location.
        QMetaObject::invokeMethod(
            q,
            [this]() {
                slotResult(VerificationResult{Error::fromCode(GPG_ERR_EEXIST)});
            },
            Qt::QueuedConnection);
        return;
    }
#endif
    try {
        std::unique_ptr<QGpgME::VerifyOpaqueJob> job{m_backend->verifyOpaqueJob()};
        kleo_assert(job);
        connect(job.get(), &QGpgME::VerifyOpaqueJob::result, q, [this](const GpgME::VerificationResult &result, const QByteArray &plainText) {
            slotResult(result, plainText);
        });
        connect(job.get(), &QGpgME::Job::jobProgress, q, &VerifyOpaqueTask::setProgress);
#if QGPGME_SUPPORTS_PROCESS_ALL_SIGNATURES
        job->setProcessAllSignatures(true);
#endif
#if QGPGME_FILE_JOBS_SUPPORT_DIRECT_FILE_IO
        if (!m_inputFilePath.isEmpty() && !m_outputFilePath.isEmpty()) {
            job->setInputFile(m_inputFilePath);
            job->setOutputFile(m_outputFilePath);
            const auto err = job->startIt();
        } else {
            ensureIOOpen(m_input->ioDevice().get(), m_output ? m_output->ioDevice().get() : nullptr);
            job->start(m_input->ioDevice(), m_output ? m_output->ioDevice() : std::shared_ptr<QIODevice>());
        }
#else
        ensureIOOpen(m_input->ioDevice().get(), m_output ? m_output->ioDevice().get() : nullptr);
        job->start(m_input->ioDevice(), m_output ? m_output->ioDevice() : std::shared_ptr<QIODevice>());
#endif
        q->setJob(job.release());
    } catch (const GpgME::Exception &e) {
        q->emitResult(q->fromVerifyOpaqueResult(e.error(), QString::fromLocal8Bit(e.what()), AuditLogEntry()));
    } catch (const std::exception &e) {
        q->emitResult(
            q->fromVerifyOpaqueResult(Error::fromCode(GPG_ERR_INTERNAL), i18n("Caught exception: %1", QString::fromLocal8Bit(e.what())), AuditLogEntry()));
    } catch (...) {
        q->emitResult(q->fromVerifyOpaqueResult(Error::fromCode(GPG_ERR_INTERNAL), i18n("Caught unknown exception"), AuditLogEntry()));
    }
}

void VerifyOpaqueTask::Private::startDecryptVerifyArchiveJob()
{
    std::unique_ptr<QGpgME::DecryptVerifyArchiveJob> job{m_backend->decryptVerifyArchiveJob()};
    kleo_assert(job);
    connect(job.get(), &QGpgME::DecryptVerifyArchiveJob::result, q, [this](const DecryptionResult &, const VerificationResult &verifyResult) {
        slotResult(verifyResult);
    });
    connect(job.get(), &QGpgME::DecryptVerifyArchiveJob::dataProgress, q, &VerifyOpaqueTask::setProgress);
    // make sure that we don't use an existing output directory
    const auto outputDirectory = ensureUniqueDirectory(m_outputDirectory);
    if (outputDirectory.isEmpty()) {
        q->emitResult(q->fromDecryptVerifyResult(Error::fromCode(GPG_ERR_GENERAL), {}, {}));
        return;
    }
    m_outputFilePath = outputDirectory;
    m_outputDirectory = outputDirectory;
#if QGPGME_SUPPORTS_PROCESS_ALL_SIGNATURES
    job->setProcessAllSignatures(true);
#endif
    job->setInputFile(m_inputFilePath);
    job->setOutputDirectory(m_outputDirectory);
    const auto err = job->startIt();
    q->setJob(job.release());
    if (err) {
        q->emitResult(q->fromVerifyOpaqueResult(err, {}, {}));
    }
}

class VerifyDetachedTask::Private
{
    VerifyDetachedTask *const q;

public:
    explicit Private(VerifyDetachedTask *qq)
        : q{qq}
    {
    }

    void slotResult(const VerificationResult &);

    void registerJob(QGpgME::VerifyDetachedJob *job)
    {
        q->connect(job, SIGNAL(result(GpgME::VerificationResult)), q, SLOT(slotResult(GpgME::VerificationResult)));
        q->connect(job, &QGpgME::Job::jobProgress, q, &VerifyDetachedTask::setProgress);
    }

    QString signatureLabel() const;
    QString signedDataLabel() const;

    std::shared_ptr<Input> m_input, m_signedData;
    const QGpgME::Protocol *m_backend = nullptr;
    Protocol m_protocol = UnknownProtocol;
    QString m_signatureFilePath;
    QString m_signedFilePath;
};

void VerifyDetachedTask::Private::slotResult(const VerificationResult &result)
{
    updateKeys(result);
    {
        std::stringstream ss;
        ss << result;
        qCDebug(KLEOPATRA_LOG) << ss.str().c_str();
    }
    const AuditLogEntry auditLog = auditLogFromSender(q->sender());
    try {
        kleo_assert(!result.isNull());
        q->emitResult(q->fromVerifyDetachedResult(result, auditLog));
    } catch (const GpgME::Exception &e) {
        q->emitResult(q->fromVerifyDetachedResult(e.error(), QString::fromLocal8Bit(e.what()), auditLog));
    } catch (const std::exception &e) {
        q->emitResult(q->fromVerifyDetachedResult(Error::fromCode(GPG_ERR_INTERNAL), i18n("Caught exception: %1", QString::fromLocal8Bit(e.what())), auditLog));
    } catch (...) {
        q->emitResult(q->fromVerifyDetachedResult(Error::fromCode(GPG_ERR_INTERNAL), i18n("Caught unknown exception"), auditLog));
    }
}

QString VerifyDetachedTask::Private::signatureLabel() const
{
    return m_input ? m_input->label() : m_signatureFilePath;
}

QString VerifyDetachedTask::Private::signedDataLabel() const
{
    return m_signedData ? m_signedData->label() : m_signedFilePath;
}

VerifyDetachedTask::VerifyDetachedTask(QObject *parent)
    : AbstractDecryptVerifyTask(parent)
    , d(new Private(this))
{
}

VerifyDetachedTask::~VerifyDetachedTask()
{
}

void VerifyDetachedTask::setInput(const std::shared_ptr<Input> &input)
{
    d->m_input = input;
    kleo_assert(d->m_input && d->m_input->ioDevice());
}

void VerifyDetachedTask::setSignedData(const std::shared_ptr<Input> &signedData)
{
    d->m_signedData = signedData;
    kleo_assert(d->m_signedData && d->m_signedData->ioDevice());
}

void VerifyDetachedTask::setSignatureFile(const QString &path)
{
    d->m_signatureFilePath = path;
}

void VerifyDetachedTask::setSignedFile(const QString &path)
{
    d->m_signedFilePath = path;
}

void VerifyDetachedTask::setProtocol(Protocol prot)
{
    kleo_assert(prot != UnknownProtocol);
    d->m_protocol = prot;
    d->m_backend = (prot == GpgME::OpenPGP) ? QGpgME::openpgp() : QGpgME::smime();
    kleo_assert(d->m_backend);
}

void VerifyDetachedTask::autodetectProtocolFromInput()
{
    if (!d->m_input) {
        return;
    }
    const Protocol p = findProtocol(d->m_input->classification());
    if (p == UnknownProtocol) {
        throw Exception(gpg_error(GPG_ERR_NOTHING_FOUND),
                        i18n("Could not determine whether this is an S/MIME or an OpenPGP signature - maybe it is not a signature at all?"),
                        Exception::MessageOnly);
    }
    setProtocol(p);
}

unsigned long long VerifyDetachedTask::inputSize() const
{
    return d->m_signedData ? d->m_signedData->size() : 0;
}

QString VerifyDetachedTask::label() const
{
    const QString signedDataLabel = d->signedDataLabel();
    if (!signedDataLabel.isEmpty()) {
        return xi18nc(
            "Verification of a detached signature in progress. The first file contains the data."
            "The second file is the signature file.",
            "Verifying <filename>%1</filename> with <filename>%2</filename>...",
            signedDataLabel,
            d->signatureLabel());
    }
    return i18n("Verifying signature %1...", d->signatureLabel());
}

QString VerifyDetachedTask::inputLabel() const
{
    return d->signatureLabel();
}

QString VerifyDetachedTask::outputLabel() const
{
    return d->signedDataLabel();
}

Protocol VerifyDetachedTask::protocol() const
{
    return d->m_protocol;
}

void VerifyDetachedTask::doStart()
{
    kleo_assert(d->m_backend);
    try {
        std::unique_ptr<QGpgME::VerifyDetachedJob> job{d->m_backend->verifyDetachedJob()};
        kleo_assert(job);
        d->registerJob(job.get());
#if QGPGME_SUPPORTS_PROCESS_ALL_SIGNATURES
        job->setProcessAllSignatures(true);
#endif
#if QGPGME_FILE_JOBS_SUPPORT_DIRECT_FILE_IO
        if (d->m_protocol == GpgME::OpenPGP && !d->m_signatureFilePath.isEmpty() && !d->m_signedFilePath.isEmpty()) {
            job->setSignatureFile(d->m_signatureFilePath);
            job->setSignedFile(d->m_signedFilePath);
            job->startIt();
        } else {
            ensureIOOpen(d->m_input->ioDevice().get(), nullptr);
            ensureIOOpen(d->m_signedData->ioDevice().get(), nullptr);
            job->start(d->m_input->ioDevice(), d->m_signedData->ioDevice());
        }
#else
        ensureIOOpen(d->m_input->ioDevice().get(), nullptr);
        ensureIOOpen(d->m_signedData->ioDevice().get(), nullptr);
        job->start(d->m_input->ioDevice(), d->m_signedData->ioDevice());
#endif
        setJob(job.release());
    } catch (const GpgME::Exception &e) {
        emitResult(fromVerifyDetachedResult(e.error(), QString::fromLocal8Bit(e.what()), AuditLogEntry()));
    } catch (const std::exception &e) {
        emitResult(
            fromVerifyDetachedResult(Error::fromCode(GPG_ERR_INTERNAL), i18n("Caught exception: %1", QString::fromLocal8Bit(e.what())), AuditLogEntry()));
    } catch (...) {
        emitResult(fromVerifyDetachedResult(Error::fromCode(GPG_ERR_INTERNAL), i18n("Caught unknown exception"), AuditLogEntry()));
    }
}

void AbstractDecryptVerifyTask::setDataSource(Task::DataSource dataSource)
{
    d->dataSource = dataSource;
}

Task::DataSource AbstractDecryptVerifyTask::dataSource() const
{
    return d->dataSource;
}

#include "moc_decryptverifytask.cpp"
