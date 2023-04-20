/* -*- mode: c++; c-basic-offset:4 -*-
    newcertificatewizard/keycreationpage.cpp

    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2008 Klarälvdalens Datakonsult AB
    SPDX-FileCopyrightText: 2016, 2017 Bundesamt für Sicherheit in der Informationstechnik
    SPDX-FileContributor: Intevation GmbH
    SPDX-FileCopyrightText: 2022 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include <config-kleopatra.h>

#include "keycreationpage_p.h"

#include "keyalgo_p.h"

#include "kleopatraapplication.h"

#include "utils/keyparameters.h"
#include "utils/keyusage.h"

#include <Libkleo/Formatting>
#include <Libkleo/KeyCache>

#include <KConfigGroup>
#include <KLocalizedString>
#include <KSharedConfig>

#include <QGpgME/KeyGenerationJob>
#include <QGpgME/Protocol>

#include <QLabel>
#include <QUrl>
#include <QVBoxLayout>

#include <gpgme++/context.h>
#include <gpgme++/keygenerationresult.h>

#include "kleopatra_debug.h"

using namespace Kleo;
using namespace Kleo::NewCertificateUi;
using namespace GpgME;

struct KeyCreationPage::UI
{
    UI(QWizardPage *parent)
    {
        parent->setTitle(i18nc("@title", "Creating Key Pair..."));

        auto mainLayout = new QVBoxLayout{parent};

        auto label = new QLabel{i18n("The process of creating a key requires large amounts of random numbers. This may require several minutes..."), parent};
        label->setWordWrap(true);
        mainLayout->addWidget(label);
    }
};

KeyCreationPage::KeyCreationPage(QWidget *p)
    : WizardPage{p}
    , ui{new UI{this}}
{
    setObjectName(QString::fromUtf8("Kleo__NewCertificateUi__KeyCreationPage"));
}

KeyCreationPage::~KeyCreationPage() = default;

bool KeyCreationPage::isComplete() const
{
    return !job;
}

void KeyCreationPage::initializePage()
{
    startJob();
}

void KeyCreationPage::startJob()
{
    const auto proto = pgp() ? QGpgME::openpgp() : QGpgME::smime();
    if (!proto) {
        return;
    }
    QGpgME::KeyGenerationJob *const j = proto->keyGenerationJob();
    if (!j) {
        return;
    }
    if (!protectedKey() && pgp()) {
        auto ctx = QGpgME::Job::context(j);
        ctx->setPassphraseProvider(&mEmptyPassphraseProvider);
        ctx->setPinentryMode(Context::PinentryLoopback);
    }
    connect(j, &QGpgME::KeyGenerationJob::result,
            this, &KeyCreationPage::slotResult);
    if (const Error err = j->start(createGnupgKeyParms()))
        setField(QStringLiteral("error"), i18n("Could not start key pair creation: %1",
                                                Formatting::errorAsString(err)));
    else {
        job = j;
    }
}

KeyUsage KeyCreationPage::keyUsage() const
{
    KeyUsage usage;
    if (signingAllowed()) {
        usage.setCanSign(true);
    }
    if (encryptionAllowed() && !is_ecdh(subkeyType()) &&
        !is_dsa(keyType()) && !is_rsa(subkeyType())) {
        usage.setCanEncrypt(true);
    }
    if (authenticationAllowed()) {
        usage.setCanAuthenticate(true);
    }
    if (!usage.value() && certificationAllowed()) {
        /* Empty usages cause an error so we need to
         * add at least certify if nothing else is selected */
        usage.setCanCertify(true);
    }
    return usage;
}

KeyUsage KeyCreationPage::subkeyUsage() const
{
    KeyUsage usage;
    if (encryptionAllowed() && (is_dsa(keyType()) || is_rsa(subkeyType()) ||
                                is_ecdh(subkeyType()))) {
        Q_ASSERT(subkeyType());
        usage.setCanEncrypt(true);
    }
    return usage;
}

QString KeyCreationPage::createGnupgKeyParms() const
{
    KeyParameters keyParameters(pgp() ? KeyParameters::OpenPGP : KeyParameters::CMS);

    keyParameters.setKeyType(keyType());
    if (is_ecdsa(keyType()) || is_eddsa(keyType())) {
        keyParameters.setKeyCurve(keyCurve());
    } else if (const unsigned int strength = keyStrength()) {
        keyParameters.setKeyLength(strength);
    }
    keyParameters.setKeyUsage(keyUsage());

    if (subkeyType()) {
        keyParameters.setSubkeyType(subkeyType());
        if (is_ecdh(subkeyType())) {
            keyParameters.setSubkeyCurve(subkeyCurve());
        } else if (const unsigned int strength = subkeyStrength()) {
            keyParameters.setSubkeyLength(strength);
        }
        keyParameters.setSubkeyUsage(subkeyUsage());
    }

    if (pgp()) {
        if (expiryDate().isValid()) {
            keyParameters.setExpirationDate(expiryDate());
        }
        if (!name().isEmpty()) {
            keyParameters.setName(name());
        }
        if (!email().isEmpty()) {
            keyParameters.setEmail(email());
        }
    } else {
        keyParameters.setDN(dn());
        keyParameters.setEmail(email());
        const auto addesses{additionalEMailAddresses()};
        for (const QString &email : addesses) {
            keyParameters.addEmail(email);
        }
        const auto dnsN{dnsNames()};
        for (const QString &dns : dnsN) {
            keyParameters.addDomainName(dns);
        }
        const auto urisList{uris()};
        for (const QString &uri : urisList) {
            keyParameters.addURI(uri);
        }
    }

    const QString result = keyParameters.toString();
    qCDebug(KLEOPATRA_LOG) << '\n' << result;
    return result;
}

void KeyCreationPage::slotResult(const GpgME::KeyGenerationResult &result, const QByteArray &request, const QString &auditLog)
{
    Q_UNUSED(auditLog)
    if (result.error().code() || (pgp() && !result.fingerprint())) {
        setField(QStringLiteral("error"), result.error().isCanceled()
                    ? i18n("Operation canceled.")
                    : i18n("Could not create key pair: %1",
                        Formatting::errorAsString(result.error())));
        setField(QStringLiteral("url"), QString());
        setField(QStringLiteral("result"), QString());
    } else if (pgp()) {
        setField(QStringLiteral("error"), QString());
        setField(QStringLiteral("url"), QString());
        setField(QStringLiteral("result"), i18n("Key pair created successfully.\n"
                                                "Fingerprint: %1", Formatting::prettyID(result.fingerprint())));
    } else {
        QFile file(tmpDir().absoluteFilePath(QStringLiteral("request.p10")));

        if (!file.open(QIODevice::WriteOnly)) {
            setField(QStringLiteral("error"), i18n("Could not write output file %1: %2",
                                                    file.fileName(), file.errorString()));
            setField(QStringLiteral("url"), QString());
            setField(QStringLiteral("result"), QString());
        } else {
            file.write(request);
            setField(QStringLiteral("error"), QString());
            setField(QStringLiteral("url"), QUrl::fromLocalFile(file.fileName()).toString());
            setField(QStringLiteral("result"), i18n("Key pair created successfully."));
        }
    }
    // Ensure that we have the key in the keycache
    if (pgp() && !result.error().code() && result.fingerprint()) {
        auto ctx = Context::createForProtocol(OpenPGP);
        if (ctx) {
            // Check is pretty useless something very buggy in that case.
            Error e;
            const auto key = ctx->key(result.fingerprint(), e, true);
            if (!key.isNull()) {
                KeyCache::mutableInstance()->insert(key);
            } else {
                qCDebug(KLEOPATRA_LOG) << "Failed to find newly generated key.";
            }
            delete ctx;
        }
    }
    setField(QStringLiteral("fingerprint"), result.fingerprint() ?
                QString::fromLatin1(result.fingerprint()) : QString());
    job = nullptr;
    Q_EMIT completeChanged();
    const KConfigGroup config(KSharedConfig::openConfig(), "CertificateCreationWizard");
    if (config.readEntry("SkipResultPage", false)) {
        if (result.fingerprint()) {
            KleopatraApplication::instance()->slotActivateRequested(QStringList() <<
                    QStringLiteral("kleopatra") << QStringLiteral("--query") << QLatin1String(result.fingerprint()), QString());
            QMetaObject::invokeMethod(wizard(), "close", Qt::QueuedConnection);
        } else {
            QMetaObject::invokeMethod(wizard(), "next", Qt::QueuedConnection);
        }
    } else {
        QMetaObject::invokeMethod(wizard(), "next", Qt::QueuedConnection);
    }
}
