/*
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

#include "kleopatraapplication.h"

#include <Libkleo/Formatting>
#include <Libkleo/KeyCache>
#include <Libkleo/KeyParameters>
#include <Libkleo/KeyUsage>

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

struct KeyCreationPage::UI {
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
    auto j = QGpgME::smime()->keyGenerationJob();
    if (!j) {
        return;
    }
    connect(j, &QGpgME::KeyGenerationJob::result, this, &KeyCreationPage::slotResult);
    if (const Error err = j->start(createGnupgKeyParms()))
        setField(QStringLiteral("error"), i18n("Could not start key pair creation: %1", Formatting::errorAsString(err)));
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
    if (encryptionAllowed()) {
        usage.setCanEncrypt(true);
    }
    return usage;
}

QString KeyCreationPage::createGnupgKeyParms() const
{
    KeyParameters keyParameters(KeyParameters::CMS);

    keyParameters.setKeyType(keyType());
    if (const unsigned int strength = keyStrength()) {
        keyParameters.setKeyLength(strength);
    }
    keyParameters.setKeyUsage(keyUsage());

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

    const QString result = keyParameters.toString();
    qCDebug(KLEOPATRA_LOG) << '\n' << result;
    return result;
}

void KeyCreationPage::slotResult(const GpgME::KeyGenerationResult &result, const QByteArray &request, const QString &auditLog)
{
    Q_UNUSED(auditLog)
    if (result.error().code()) {
        setField(QStringLiteral("error"),
                 result.error().isCanceled() ? i18n("Operation canceled.") : i18n("Could not create key pair: %1", Formatting::errorAsString(result.error())));
        setField(QStringLiteral("url"), QString());
        setField(QStringLiteral("result"), QString());
    } else {
        QFile file(tmpDir().absoluteFilePath(QStringLiteral("request.p10")));

        if (!file.open(QIODevice::WriteOnly)) {
            setField(QStringLiteral("error"), i18n("Could not write output file %1: %2", file.fileName(), file.errorString()));
            setField(QStringLiteral("url"), QString());
            setField(QStringLiteral("result"), QString());
        } else {
            file.write(request);
            setField(QStringLiteral("error"), QString());
            setField(QStringLiteral("url"), QUrl::fromLocalFile(file.fileName()).toString());
            setField(QStringLiteral("result"), i18n("Key pair created successfully."));
        }
    }

    setField(QStringLiteral("fingerprint"), result.fingerprint() ? QString::fromLatin1(result.fingerprint()) : QString());
    job = nullptr;
    Q_EMIT completeChanged();
    const KConfigGroup config(KSharedConfig::openConfig(), QStringLiteral("CertificateCreationWizard"));
    if (config.readEntry("SkipResultPage", false)) {
        if (result.fingerprint()) {
            KleopatraApplication::instance()->slotActivateRequested(QStringList() << QStringLiteral("kleopatra") << QStringLiteral("--query")
                                                                                  << QLatin1StringView(result.fingerprint()),
                                                                    QString());
            QMetaObject::invokeMethod(wizard(), "close", Qt::QueuedConnection);
        } else {
            QMetaObject::invokeMethod(wizard(), "next", Qt::QueuedConnection);
        }
    } else {
        QMetaObject::invokeMethod(wizard(), "next", Qt::QueuedConnection);
    }
}

#include "moc_keycreationpage_p.cpp"
