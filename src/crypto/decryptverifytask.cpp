/* -*- mode: c++; c-basic-offset:4 -*-
    decryptverifytask.cpp

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

static std::vector<QString> extractEmails(const std::vector<Key> &signers)
{
    std::vector<QString> res;
    for (const Key &i : signers) {
        const std::vector<QString> bxs = extractEmails(i);
        res.insert(res.end(), bxs.begin(), bxs.end());
    }
    return res;
}

static bool keyContainsEmail(const Key &key, const QString &email)
{
    const std::vector<QString> emails = extractEmails(key);
    return std::find_if(emails.cbegin(),
                        emails.cend(),
                        [email](const QString &emailItem) {
                            return emailItem.compare(email, Qt::CaseInsensitive);
                        })
        != emails.cend();
}

static bool keysContainEmail(const std::vector<Key> &keys, const QString &email)
{
    return std::find_if(keys.cbegin(),
                        keys.cend(),
                        [email](const Key &key) {
                            return keyContainsEmail(key, email);
                        })
        != keys.cend();
}

static bool relevantInDecryptVerifyContext(const VerificationResult &r)
{
    // for D/V operations, we ignore verification results which are not errors and contain
    // no signatures (which means that the data was just not signed)

    return (r.error() && r.error().code() != GPG_ERR_DECRYPT_FAILED) || r.numSignatures() > 0;
}

static QString renderKeyLink(const QString &fpr, const QString &text)
{
    return QStringLiteral("<a href=\"key:%1\">%2</a>").arg(fpr, text);
}

static QString renderKey(const Key &key)
{
    if (key.isNull()) {
        return i18n("Unknown certificate");
    }

    if (key.primaryFingerprint() && strlen(key.primaryFingerprint()) > 16 && key.numUserIDs()) {
        const QString text = QStringLiteral("%1 (%2)")
                                 .arg(Formatting::prettyNameAndEMail(key).toHtmlEscaped())
                                 .arg(Formatting::prettyID(QString::fromLocal8Bit(key.primaryFingerprint()).right(16).toLatin1().constData()));
        return renderKeyLink(QLatin1StringView(key.primaryFingerprint()), text);
    }

    return renderKeyLink(QLatin1StringView(key.primaryFingerprint()), Formatting::prettyID(key.primaryFingerprint()));
}

static QString renderKeyEMailOnlyNameAsFallback(const Key &key)
{
    if (key.isNull()) {
        return i18n("Unknown certificate");
    }
    const QString email = Formatting::prettyEMail(key);
    const QString user = !email.isEmpty() ? email : Formatting::prettyName(key);
    return renderKeyLink(QLatin1StringView(key.primaryFingerprint()), user);
}

static QString strikeOut(const QString &str, bool strike)
{
    return QString(strike ? QStringLiteral("<s>%1</s>") : QStringLiteral("%1")).arg(str.toHtmlEscaped());
}

static QString formatInputOutputLabel(const QString &input, const QString &output, bool inputDeleted, bool outputDeleted)
{
    if (output.isEmpty()) {
        return strikeOut(input, inputDeleted);
    }
    return i18nc("Input file --> Output file (rarr is arrow", "%1 &rarr; %2", strikeOut(input, inputDeleted), strikeOut(output, outputDeleted));
}

static bool IsErrorOrCanceled(const GpgME::Error &err)
{
    return err || err.isCanceled();
}

static bool IsErrorOrCanceled(const Result &res)
{
    return IsErrorOrCanceled(res.error());
}

static bool IsBad(const Signature &sig)
{
    return sig.summary() & Signature::Red;
}

static bool IsGoodOrValid(const Signature &sig)
{
    return (sig.summary() & Signature::Valid) || (sig.summary() & Signature::Green);
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

class DecryptVerifyResult::SenderInfo
{
public:
    explicit SenderInfo(const QString &infSender, const std::vector<Key> &signers_)
        : informativeSender(infSender)
        , signers(signers_)
    {
    }
    const QString informativeSender;
    const std::vector<Key> signers;
    bool hasInformativeSender() const
    {
        return !informativeSender.isEmpty();
    }
    bool conflicts() const
    {
        return hasInformativeSender() && hasKeys() && !keysContainEmail(signers, informativeSender);
    }
    bool hasKeys() const
    {
        return std::any_of(signers.cbegin(), signers.cend(), [](const Key &key) {
            return !key.isNull();
        });
    }
    std::vector<QString> signerEmails() const
    {
        return extractEmails(signers);
    }
};

namespace
{

static Task::Result::VisualCode codeForVerificationResult(const VerificationResult &res)
{
    if (res.isNull()) {
        return Task::Result::NeutralSuccess;
    }

    const std::vector<Signature> sigs = res.signatures();
    if (sigs.empty()) {
        return Task::Result::Warning;
    }

    if (std::find_if(sigs.begin(), sigs.end(), IsBad) != sigs.end()) {
        return Task::Result::Danger;
    }

    if ((size_t)std::count_if(sigs.begin(), sigs.end(), IsGoodOrValid) == sigs.size()) {
        return Task::Result::AllGood;
    }

    return Task::Result::Warning;
}

static QString formatVerificationResultOverview(const VerificationResult &res, const DecryptVerifyResult::SenderInfo &info)
{
    if (res.isNull()) {
        return QString();
    }

    const Error err = res.error();

    if (err.isCanceled()) {
        return i18n("<b>Verification canceled.</b>");
    } else if (err) {
        return i18n("<b>Verification failed: %1.</b>", Formatting::errorAsString(err).toHtmlEscaped());
    }

    const std::vector<Signature> sigs = res.signatures();

    if (sigs.empty()) {
        return i18n("<b>No signatures found.</b>");
    }

    const uint bad = std::count_if(sigs.cbegin(), sigs.cend(), IsBad);
    if (bad > 0) {
        return i18np("<b>Invalid signature.</b>", "<b>%1 invalid signatures.</b>", bad);
    }
    const uint warn = std::count_if(sigs.cbegin(), sigs.cend(), [](const Signature &sig) {
        return !IsGoodOrValid(sig);
    });
    if (warn == sigs.size()) {
        return i18np("<b>The data could not be verified.</b>", "<b>%1 signatures could not be verified.</b>", warn);
    }

    // Good signature:
    QString text;
    if (sigs.size() == 1) {
        text = i18n("<b>Valid signature by %1</b>", renderKeyEMailOnlyNameAsFallback(sigs[0].key()));
        if (info.conflicts())
            text += i18n("<br/><b>Warning:</b> The sender's mail address is not stored in the %1 used for signing.",
                         renderKeyLink(QLatin1StringView(sigs[0].key().primaryFingerprint()), i18n("certificate")));
    } else {
        text = i18np("<b>Valid signature.</b>", "<b>%1 valid signatures.</b>", sigs.size());
        if (info.conflicts()) {
            text += i18n("<br/><b>Warning:</b> The sender's mail address is not stored in the certificates used for signing.");
        }
    }

    return text;
}

static QString formatDecryptionResultOverview(const DecryptionResult &result, const QString &errorString = QString())
{
    const Error err = result.error();

    if (err.isCanceled()) {
        return i18n("<b>Decryption canceled.</b>");
    } else if (result.isLegacyCipherNoMDC()) {
        return i18n("<b>Decryption failed: %1.</b>", i18n("No integrity protection (MDC)."));
    } else if (!errorString.isEmpty()) {
        return i18n("<b>Decryption failed: %1.</b>", errorString.toHtmlEscaped());
    } else if (err) {
        return i18n("<b>Decryption failed: %1.</b>", Formatting::errorAsString(err).toHtmlEscaped());
    }
    return i18n("<b>Decryption succeeded.</b>");
}

static QString formatEmail(const QString &email_)
{
    QString email;
    QString name;
    QString comment;
    if (!email_.isEmpty() && KEmailAddress::splitAddress(email_, name, email, comment) == KEmailAddress::AddressOk) {
        return email;
    }
    return email_;
}

static QStringList formatEmails(const std::vector<QString> &emails)
{
    QStringList res;
    std::transform(emails.cbegin(), emails.cend(), std::back_inserter(res), &formatEmail);
    return res;
}

static QString formatVerificationResultDetails(const VerificationResult &res, const DecryptVerifyResult::SenderInfo &info, const QString &errorString)
{
    if ((res.error().code() == GPG_ERR_EIO || res.error().code() == GPG_ERR_NO_DATA) && !errorString.isEmpty()) {
        return i18n("Input error: %1", errorString);
    }

    const std::vector<Signature> sigs = res.signatures();
    QString details;
    for (const Signature &sig : sigs) {
        details += Kleo::Formatting::prettySignature(sig, info.informativeSender) + QLatin1Char('\n');
    }
    details = details.trimmed();
    details.replace(QLatin1Char('\n'), QStringLiteral("<br/><br/>"));
    if (info.conflicts()) {
        details += i18n("<p>The sender's address %1 is not stored in the certificate. Stored: %2</p>",
                        formatEmail(info.informativeSender),
                        formatEmails(info.signerEmails()).join(i18nc("separator for a list of e-mail addresses", ", ")));
    }
    return details;
}

static QString formatRecipientsDetails(const std::vector<Key> &knownRecipients, unsigned int numRecipients)
{
    if (numRecipients == 0) {
        return {};
    }

    if (knownRecipients.empty()) {
        return QLatin1StringView("<i>") + i18np("One unknown recipient.", "%1 unknown recipients.", numRecipients) + QLatin1StringView("</i>");
    }

    QString details = i18np("Recipient:", "Recipients:", numRecipients);

    if (numRecipients == 1) {
        details += QLatin1Char(' ') + renderKey(knownRecipients.front());
    } else {
        details += QLatin1StringView("<ul>");
        for (const Key &key : knownRecipients) {
            details += QLatin1StringView("<li>") + renderKey(key) + QLatin1StringView("</li>");
        }
        if (knownRecipients.size() < numRecipients) {
            details += QLatin1StringView("<li><i>") + i18np("One unknown recipient", "%1 unknown recipients", numRecipients - knownRecipients.size())
                + QLatin1StringView("</i></li>");
        }
        details += QLatin1StringView("</ul>");
    }

    return details;
}

static QString formatDecryptionResultDetails(const DecryptionResult &res,
                                             const std::vector<Key> &recipients,
                                             const QString &errorString,
                                             bool isSigned,
                                             const QPointer<Task> &task)
{
    if ((res.error().code() == GPG_ERR_EIO || res.error().code() == GPG_ERR_NO_DATA) && !errorString.isEmpty()) {
        return i18n("Input error: %1", errorString);
    }

    if (res.isNull() || res.error() || res.error().isCanceled()) {
        return formatRecipientsDetails(recipients, res.numRecipients());
    }

    QString details;

    if (DeVSCompliance::isCompliant()) {
        details += ((res.isDeVs() ? i18nc("%1 is a placeholder for the name of a compliance mode. E.g. NATO RESTRICTED compliant or VS-NfD compliant",
                                          "The decryption is %1.",
                                          DeVSCompliance::name(true))
                                  : i18nc("%1 is a placeholder for the name of a compliance mode. E.g. NATO RESTRICTED compliant or VS-NfD compliant",
                                          "The decryption <b>is not</b> %1.",
                                          DeVSCompliance::name(true)))
                    + QStringLiteral("<br/>"));
    }

    if (res.fileName()) {
        const auto decVerifyTask = qobject_cast<AbstractDecryptVerifyTask *>(task.data());
        if (decVerifyTask) {
            const auto embedFileName = QString::fromUtf8(res.fileName()).toHtmlEscaped();

            if (embedFileName != decVerifyTask->outputLabel()) {
                details += i18n("Embedded file name: '%1'", embedFileName);
                details += QStringLiteral("<br/>");
            }
        }
    }

    if (!isSigned) {
        details += i18n("<b>Note:</b> You cannot be sure who encrypted this message as it is not signed.") + QLatin1StringView("<br/>");
    }

    if (res.isLegacyCipherNoMDC()) {
        details += i18nc("Integrity protection was missing because an old cipher was used.",
                         "<b>Hint:</b> If this file was encrypted before the year 2003 it is "
                         "likely that the file is legitimate.  This is because back "
                         "then integrity protection was not widely used.")
            + QStringLiteral("<br/><br/>")
            + i18nc("The user is offered to force decrypt a non integrity protected message. With the strong advice to re-encrypt it.",
                    "If you are confident that the file was not manipulated you should re-encrypt it after you have forced the decryption.")
            + QStringLiteral("<br/><br/>");
    }

    details += formatRecipientsDetails(recipients, res.numRecipients());

    return details;
}

static QString formatDecryptVerifyResultOverview(const DecryptionResult &dr, const VerificationResult &vr, const DecryptVerifyResult::SenderInfo &info)
{
    if (IsErrorOrCanceled(dr) || !relevantInDecryptVerifyContext(vr)) {
        return formatDecryptionResultOverview(dr);
    }
    return formatVerificationResultOverview(vr, info);
}

static QString formatDecryptVerifyResultDetails(const DecryptionResult &dr,
                                                const VerificationResult &vr,
                                                const std::vector<Key> &recipients,
                                                const DecryptVerifyResult::SenderInfo &info,
                                                const QString &errorString,
                                                const QPointer<Task> &task)
{
    const QString drDetails = formatDecryptionResultDetails(dr, recipients, errorString, relevantInDecryptVerifyContext(vr), task);
    if (IsErrorOrCanceled(dr) || !relevantInDecryptVerifyContext(vr)) {
        return drDetails;
    }
    return drDetails + (drDetails.isEmpty() ? QString() : QStringLiteral("<br/>")) + formatVerificationResultDetails(vr, info, errorString);
}

} // anon namespace

class DecryptVerifyResult::Private
{
    DecryptVerifyResult *const q;

public:
    Private(DecryptVerifyOperation type,
            const VerificationResult &vr,
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
            DecryptVerifyResult *qq)
        : q(qq)
        , m_type(type)
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
    }

    QString label() const
    {
        return formatInputOutputLabel(m_inputLabel, m_outputLabel, false, q->hasError());
    }

    DecryptVerifyResult::SenderInfo makeSenderInfo() const;

    bool isDecryptOnly() const
    {
        return m_type == Decrypt;
    }
    bool isVerifyOnly() const
    {
        return m_type == Verify;
    }
    bool isDecryptVerify() const
    {
        return m_type == DecryptVerify;
    }
    DecryptVerifyOperation m_type;
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

DecryptVerifyResult::SenderInfo DecryptVerifyResult::Private::makeSenderInfo() const
{
    return SenderInfo(QString::fromUtf8(m_informativeSender.address()), KeyCache::instance()->findSigners(m_verificationResult));
}

std::shared_ptr<DecryptVerifyResult>
AbstractDecryptVerifyTask::fromDecryptResult(const DecryptionResult &dr, const QByteArray &plaintext, const AuditLogEntry &auditLog)
{
    return std::shared_ptr<DecryptVerifyResult>(new DecryptVerifyResult(Decrypt, //
                                                                        VerificationResult(),
                                                                        dr,
                                                                        plaintext,
                                                                        {},
                                                                        {},
                                                                        QString(),
                                                                        inputLabel(),
                                                                        outputLabel(),
                                                                        auditLog,
                                                                        this,
                                                                        informativeSender()));
}

std::shared_ptr<DecryptVerifyResult> AbstractDecryptVerifyTask::fromDecryptResult(const GpgME::Error &err, const QString &what, const AuditLogEntry &auditLog)
{
    return std::shared_ptr<DecryptVerifyResult>(new DecryptVerifyResult(Decrypt, //
                                                                        VerificationResult(),
                                                                        DecryptionResult(err),
                                                                        QByteArray(),
                                                                        {},
                                                                        err,
                                                                        what,
                                                                        inputLabel(),
                                                                        outputLabel(),
                                                                        auditLog,
                                                                        this,
                                                                        informativeSender()));
}

std::shared_ptr<DecryptVerifyResult> AbstractDecryptVerifyTask::fromDecryptVerifyResult(const DecryptionResult &dr,
                                                                                        const VerificationResult &vr,
                                                                                        const QByteArray &plaintext,
                                                                                        const QString &fileName,
                                                                                        const AuditLogEntry &auditLog)
{
    const auto err = dr.error().code() ? dr.error() : vr.error();
    return std::shared_ptr<DecryptVerifyResult>(new DecryptVerifyResult(DecryptVerify, //
                                                                        vr,
                                                                        dr,
                                                                        plaintext,
                                                                        fileName,
                                                                        err,
                                                                        QString(),
                                                                        inputLabel(),
                                                                        outputLabel(),
                                                                        auditLog,
                                                                        this,
                                                                        informativeSender()));
}

std::shared_ptr<DecryptVerifyResult>
AbstractDecryptVerifyTask::fromDecryptVerifyResult(const GpgME::Error &err, const QString &details, const AuditLogEntry &auditLog)
{
    return std::shared_ptr<DecryptVerifyResult>(new DecryptVerifyResult(DecryptVerify, //
                                                                        VerificationResult(),
                                                                        DecryptionResult(err),
                                                                        QByteArray(),
                                                                        {},
                                                                        err,
                                                                        details,
                                                                        inputLabel(),
                                                                        outputLabel(),
                                                                        auditLog,
                                                                        this,
                                                                        informativeSender()));
}

std::shared_ptr<DecryptVerifyResult>
AbstractDecryptVerifyTask::fromVerifyOpaqueResult(const VerificationResult &vr, const QByteArray &plaintext, const AuditLogEntry &auditLog)
{
    return std::shared_ptr<DecryptVerifyResult>(new DecryptVerifyResult(Verify, //
                                                                        vr,
                                                                        DecryptionResult(),
                                                                        plaintext,
                                                                        {},
                                                                        {},
                                                                        QString(),
                                                                        inputLabel(),
                                                                        outputLabel(),
                                                                        auditLog,
                                                                        this,
                                                                        informativeSender()));
}
std::shared_ptr<DecryptVerifyResult>
AbstractDecryptVerifyTask::fromVerifyOpaqueResult(const GpgME::Error &err, const QString &details, const AuditLogEntry &auditLog)
{
    return std::shared_ptr<DecryptVerifyResult>(new DecryptVerifyResult(Verify, //
                                                                        VerificationResult(err),
                                                                        DecryptionResult(),
                                                                        QByteArray(),
                                                                        {},
                                                                        err,
                                                                        details,
                                                                        inputLabel(),
                                                                        outputLabel(),
                                                                        auditLog,
                                                                        this,
                                                                        informativeSender()));
}

std::shared_ptr<DecryptVerifyResult> AbstractDecryptVerifyTask::fromVerifyDetachedResult(const VerificationResult &vr, const AuditLogEntry &auditLog)
{
    return std::shared_ptr<DecryptVerifyResult>(new DecryptVerifyResult(Verify, //
                                                                        vr,
                                                                        DecryptionResult(),
                                                                        QByteArray(),
                                                                        {},
                                                                        {},
                                                                        QString(),
                                                                        inputLabel(),
                                                                        outputLabel(),
                                                                        auditLog,
                                                                        this,
                                                                        informativeSender()));
}
std::shared_ptr<DecryptVerifyResult>
AbstractDecryptVerifyTask::fromVerifyDetachedResult(const GpgME::Error &err, const QString &details, const AuditLogEntry &auditLog)
{
    return std::shared_ptr<DecryptVerifyResult>(new DecryptVerifyResult(Verify, //
                                                                        VerificationResult(err),
                                                                        DecryptionResult(),
                                                                        QByteArray(),
                                                                        {},
                                                                        err,
                                                                        details,
                                                                        inputLabel(),
                                                                        outputLabel(),
                                                                        auditLog,
                                                                        this,
                                                                        informativeSender()));
}

DecryptVerifyResult::DecryptVerifyResult(DecryptVerifyOperation type,
                                         const VerificationResult &vr,
                                         const DecryptionResult &dr,
                                         const QByteArray &stuff,
                                         const QString &fileName,
                                         const GpgME::Error &error,
                                         const QString &errString,
                                         const QString &inputLabel,
                                         const QString &outputLabel,
                                         const AuditLogEntry &auditLog,
                                         Task *parentTask,
                                         const Mailbox &informativeSender)
    : Task::Result()
    , d(new Private(type, vr, dr, stuff, fileName, error, errString, inputLabel, outputLabel, auditLog, parentTask, informativeSender, this))
{
}

Task::Result::ContentType DecryptVerifyResult::viewableContentType() const
{
#if QGPGME_SUPPORTS_IS_MIME
    if (decryptionResult().isMime()) {
        return Task::Result::ContentType::Mime;
    }
#endif

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

QString DecryptVerifyResult::overview() const
{
    QString ov;
    if (d->isDecryptOnly()) {
        ov += formatDecryptionResultOverview(d->m_decryptionResult);
    } else if (d->isVerifyOnly()) {
        ov += formatVerificationResultOverview(d->m_verificationResult, d->makeSenderInfo());
    } else {
        ov += formatDecryptVerifyResultOverview(d->m_decryptionResult, d->m_verificationResult, d->makeSenderInfo());
    }
    if (ov.size() + d->label().size() > 120) {
        // Avoid ugly breaks
        ov = QStringLiteral("<br>") + ov;
    }
    return i18nc("label: result example: foo.sig: Verification failed. ", "%1: %2", d->label(), ov);
}

QString DecryptVerifyResult::details() const
{
    if (d->isDecryptOnly()) {
        return formatDecryptionResultDetails(d->m_decryptionResult,
                                             KeyCache::instance()->findRecipients(d->m_decryptionResult),
                                             errorString(),
                                             false,
                                             d->m_parentTask);
    }
    if (d->isVerifyOnly()) {
        return formatVerificationResultDetails(d->m_verificationResult, d->makeSenderInfo(), errorString());
    }
    return formatDecryptVerifyResultDetails(d->m_decryptionResult,
                                            d->m_verificationResult,
                                            KeyCache::instance()->findRecipients(d->m_decryptionResult),
                                            d->makeSenderInfo(),
                                            errorString(),
                                            d->m_parentTask);
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

Task::Result::VisualCode DecryptVerifyResult::code() const
{
    if ((d->m_type == DecryptVerify || d->m_type == Verify) && relevantInDecryptVerifyContext(verificationResult())) {
        return codeForVerificationResult(verificationResult());
    }
    return hasError() ? NeutralError : NeutralSuccess;
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

    q->emitResult(q->fromDecryptVerifyResult(dr, vr, plainText, m_output ? m_output->fileName() : QString{}, auditLog));
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
    const QString signatureLabel = d->signatureLabel();
    const QString signedDataLabel = d->signedDataLabel();
    if (!signedDataLabel.isEmpty() && !signatureLabel.isEmpty()) {
        return xi18nc(
            "Verification of a detached signature summary. The first file contains the data."
            "The second file is signature.",
            "Verified <filename>%1</filename> with <filename>%2</filename>",
            signedDataLabel,
            signatureLabel);
    }
    return signatureLabel;
}

QString VerifyDetachedTask::outputLabel() const
{
    return QString();
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

#include "moc_decryptverifytask.cpp"
