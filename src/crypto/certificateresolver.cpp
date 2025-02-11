/* -*- mode: c++; c-basic-offset:4 -*-
    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2007 Klarälvdalens Datakonsult AB

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include <config-kleopatra.h>

#include "certificateresolver.h"

#include <Libkleo/KeyCache>

#include <gpgme++/key.h>

#include <KConfig>
#include <KConfigGroup>
#include <QRegularExpression>

#include <QByteArray>
#include <QHash>
#include <QSet>

#include <algorithm>
#include <iterator>

using namespace Kleo;
using namespace Kleo::Crypto;
using namespace GpgME;
using namespace KMime::Types;

class KConfigBasedRecipientPreferences::Private
{
    friend class ::Kleo::Crypto::KConfigBasedRecipientPreferences;
    KConfigBasedRecipientPreferences *const q;

public:
    explicit Private(const KSharedConfigPtr &config, KConfigBasedRecipientPreferences *qq);
    ~Private();

private:
    void ensurePrefsParsed() const;
    void writePrefs();

private:
    KSharedConfigPtr m_config;

    mutable QHash<QByteArray, QByteArray> pgpPrefs;
    mutable QHash<QByteArray, QByteArray> cmsPrefs;
    mutable bool m_parsed;
    mutable bool m_dirty;
};

KConfigBasedRecipientPreferences::Private::Private(const KSharedConfigPtr &config, KConfigBasedRecipientPreferences *qq)
    : q(qq)
    , m_config(config)
    , m_parsed(false)
    , m_dirty(false)
{
    Q_UNUSED(q);
    Q_ASSERT(m_config);
}

KConfigBasedRecipientPreferences::Private::~Private()
{
    writePrefs();
}

void KConfigBasedRecipientPreferences::Private::writePrefs()
{
    if (!m_dirty) {
        return;
    }
    const auto pgpPrefsKeys = pgpPrefs.keys();
    const auto cmsPrefsKeys = cmsPrefs.keys();
    const QSet<QByteArray> keys = QSet<QByteArray>(pgpPrefsKeys.begin(), pgpPrefsKeys.end()) + QSet<QByteArray>(cmsPrefsKeys.begin(), cmsPrefsKeys.end());

    int n = 0;
    for (const QByteArray &i : keys) {
        KConfigGroup group(m_config, QStringLiteral("EncryptionPreference_%1").arg(n++));
        group.writeEntry("email", i);
        const QByteArray pgp = pgpPrefs.value(i);
        if (!pgp.isEmpty()) {
            group.writeEntry("pgpCertificate", pgp);
        }
        const QByteArray cms = cmsPrefs.value(i);
        if (!cms.isEmpty()) {
            group.writeEntry("cmsCertificate", cms);
        }
    }
    m_config->sync();
    m_dirty = false;
}
void KConfigBasedRecipientPreferences::Private::ensurePrefsParsed() const
{
    if (m_parsed) {
        return;
    }
    const QStringList groups = m_config->groupList().filter(QRegularExpression(QStringLiteral("^EncryptionPreference_\\d+$")));

    for (const QString &i : groups) {
        const KConfigGroup group(m_config, i);
        const QByteArray id = group.readEntry("email", QByteArray());
        if (id.isEmpty()) {
            continue;
        }
        pgpPrefs.insert(id, group.readEntry("pgpCertificate", QByteArray()));
        cmsPrefs.insert(id, group.readEntry("cmsCertificate", QByteArray()));
    }
    m_parsed = true;
}

KConfigBasedRecipientPreferences::KConfigBasedRecipientPreferences(const KSharedConfigPtr &config)
    : d(new Private(config, this))
{
}

KConfigBasedRecipientPreferences::~KConfigBasedRecipientPreferences()
{
    d->writePrefs();
}

Key KConfigBasedRecipientPreferences::preferredCertificate(const Mailbox &recipient, Protocol protocol)
{
    d->ensurePrefsParsed();

    const QByteArray keyId = (protocol == CMS ? d->cmsPrefs : d->pgpPrefs).value(recipient.address());
    return KeyCache::instance()->findByKeyIDOrFingerprint(keyId.constData());
}

void KConfigBasedRecipientPreferences::setPreferredCertificate(const Mailbox &recipient, Protocol protocol, const Key &certificate)
{
    d->ensurePrefsParsed();
    if (!recipient.hasAddress()) {
        return;
    }
    (protocol == CMS ? d->cmsPrefs : d->pgpPrefs).insert(recipient.address(), certificate.keyID());
    d->m_dirty = true;
}

class KConfigBasedSigningPreferences::Private
{
    friend class ::Kleo::Crypto::KConfigBasedSigningPreferences;
    KConfigBasedSigningPreferences *const q;

public:
    explicit Private(const KSharedConfigPtr &config, KConfigBasedSigningPreferences *qq);
    ~Private();

private:
    void ensurePrefsParsed() const;
    void writePrefs();

private:
    KSharedConfigPtr m_config;

    mutable QByteArray pgpSigningCertificate;
    mutable QByteArray cmsSigningCertificate;
    mutable bool m_parsed;
    mutable bool m_dirty;
};

KConfigBasedSigningPreferences::Private::Private(const KSharedConfigPtr &config, KConfigBasedSigningPreferences *qq)
    : q(qq)
    , m_config(config)
    , m_parsed(false)
    , m_dirty(false)
{
    Q_UNUSED(q);
    Q_ASSERT(m_config);
}

void KConfigBasedSigningPreferences::Private::ensurePrefsParsed() const
{
    if (m_parsed) {
        return;
    }
    const KConfigGroup group(m_config, QStringLiteral("SigningPreferences"));
    pgpSigningCertificate = group.readEntry("pgpSigningCertificate", QByteArray());
    cmsSigningCertificate = group.readEntry("cmsSigningCertificate", QByteArray());
    m_parsed = true;
}

void KConfigBasedSigningPreferences::Private::writePrefs()
{
    if (!m_dirty) {
        return;
    }
    KConfigGroup group(m_config, QStringLiteral("SigningPreferences"));
    group.writeEntry("pgpSigningCertificate", pgpSigningCertificate);
    group.writeEntry("cmsSigningCertificate", cmsSigningCertificate);
    m_config->sync();
    m_dirty = false;
}

KConfigBasedSigningPreferences::Private::~Private()
{
    writePrefs();
}

KConfigBasedSigningPreferences::KConfigBasedSigningPreferences(const KSharedConfigPtr &config)
    : d(new Private(config, this))
{
}

KConfigBasedSigningPreferences::~KConfigBasedSigningPreferences()
{
    d->writePrefs();
}

Key KConfigBasedSigningPreferences::preferredCertificate(Protocol protocol)
{
    d->ensurePrefsParsed();

    const QByteArray keyId = (protocol == CMS ? d->cmsSigningCertificate : d->pgpSigningCertificate);
    const Key key = KeyCache::instance()->findByKeyIDOrFingerprint(keyId.constData());
    return key.hasSecret() ? key : Key::null;
}

void KConfigBasedSigningPreferences::setPreferredCertificate(Protocol protocol, const Key &certificate)
{
    d->ensurePrefsParsed();
    (protocol == CMS ? d->cmsSigningCertificate : d->pgpSigningCertificate) = certificate.keyID();
    d->m_dirty = true;
}
