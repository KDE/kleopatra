/* -*- mode: c++; c-basic-offset:4 -*-
    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2009 Klarälvdalens Datakonsult AB

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include <config-kleopatra.h>

#include "sender.h"

#include <Libkleo/KeyCache>
#include <Libkleo/Predicates>
#include <Libkleo/Stl_Util>

#include <utils/cached.h>
#include <utils/kleo_assert.h>

#include <KMime/Types>

#include <gpgme++/key.h>

#include <algorithm>

using namespace Kleo;
using namespace Kleo::Crypto;
using namespace KMime::Types;
using namespace GpgME;

namespace KMime
{
namespace Types
{
static bool operator==(const AddrSpec &lhs, const AddrSpec &rhs)
{
    return lhs.localPart == rhs.localPart && lhs.domain == rhs.domain;
}

static bool operator==(const Mailbox &lhs, const Mailbox &rhs)
{
    return lhs.name() == rhs.name() && lhs.addrSpec() == rhs.addrSpec();
}

static bool determine_ambiguous(const Mailbox &mb, const std::vector<Key> &keys)
{
    Q_UNUSED(mb)
    // ### really do check when we don't only show matching keys
    return keys.size() != 1;
}
} // namespace Types
} // namespace KMime

class Sender::Private
{
    friend class ::Kleo::Crypto::Sender;

public:
    explicit Private(const Mailbox &mb)
        : mailbox(mb)
    {
        // ### also fill up to a certain number of keys with those
        // ### that don't match, for the case where there's a low
        // ### total number of keys
        const QString email = mb.addrSpec().asString();
        const std::vector<Key> signers = KeyCache::instance()->findSigningKeysByMailbox(email);
        const std::vector<Key> encrypt = KeyCache::instance()->findEncryptionKeysByMailbox(email);
        kdtools::separate_if(signers.cbegin(), signers.cend(), std::back_inserter(pgpSigners), std::back_inserter(cmsSigners), [](const Key &key) {
            return key.protocol() == OpenPGP;
        });
        kdtools::separate_if(encrypt.cbegin(),
                             encrypt.cend(),
                             std::back_inserter(pgpEncryptToSelfKeys),
                             std::back_inserter(cmsEncryptToSelfKeys),
                             [](const Key &key) {
                                 return key.protocol() == OpenPGP;
                             });
    }

private:
    const Mailbox mailbox;
    std::vector<Key> pgpSigners, cmsSigners, pgpEncryptToSelfKeys, cmsEncryptToSelfKeys;
    cached<bool> signingAmbiguous[2], encryptionAmbiguous[2];
    Key signingKey[2], cmsEncryptionKey;
    UserID pgpEncryptionUid;
};

Sender::Sender(const Mailbox &mb)
    : d(new Private(mb))
{
}

void Sender::detach()
{
    if (d && d.use_count() != 1) {
        d.reset(new Private(*d));
    }
}

bool Sender::deepEquals(const Sender &other) const
{
    static const _detail::ByFingerprint<std::equal_to> compare = {};
    return mailbox() == other.mailbox() //
        && compare(d->signingKey[CMS], other.d->signingKey[CMS]) //
        && compare(d->signingKey[OpenPGP], other.d->signingKey[OpenPGP]) //
        && compare(d->cmsEncryptionKey, other.d->cmsEncryptionKey) //
        && compare(d->pgpEncryptionUid.parent(), other.d->pgpEncryptionUid.parent()) && strcmp(d->pgpEncryptionUid.id(), other.d->pgpEncryptionUid.id()) == 0
        && std::equal(d->pgpSigners.cbegin(), d->pgpSigners.cend(), other.d->pgpSigners.cbegin(), compare)
        && std::equal(d->cmsSigners.cbegin(), d->cmsSigners.cend(), other.d->cmsSigners.cbegin(), compare)
        && std::equal(d->pgpEncryptToSelfKeys.cbegin(), d->pgpEncryptToSelfKeys.cend(), other.d->pgpEncryptToSelfKeys.cbegin(), compare)
        && std::equal(d->cmsEncryptToSelfKeys.cbegin(), d->cmsEncryptToSelfKeys.cend(), other.d->cmsEncryptToSelfKeys.cbegin(), compare);
}

bool Sender::isSigningAmbiguous(GpgME::Protocol proto) const
{
    if (d->signingAmbiguous[proto].dirty()) {
        d->signingAmbiguous[proto] = determine_ambiguous(d->mailbox, signingCertificateCandidates(proto));
    }
    return d->signingAmbiguous[proto];
}

bool Sender::isEncryptionAmbiguous(GpgME::Protocol proto) const
{
    if (d->encryptionAmbiguous[proto].dirty()) {
        d->encryptionAmbiguous[proto] = determine_ambiguous(d->mailbox, encryptToSelfCertificateCandidates(proto));
    }
    return d->encryptionAmbiguous[proto];
}

const Mailbox &Sender::mailbox() const
{
    return d->mailbox;
}

const std::vector<Key> &Sender::signingCertificateCandidates(GpgME::Protocol proto) const
{
    if (proto == OpenPGP) {
        return d->pgpSigners;
    }
    if (proto == CMS) {
        return d->cmsSigners;
    }
    kleo_assert_fail(proto == OpenPGP || proto == CMS);
#if 0
    return
        proto == OpenPGP ? d->pgpSigners :
        proto == CMS     ? d->cmsSigners :
        // even though gcc warns about this line, it's completely ok, promise:
        kleo_assert_fail(proto == OpenPGP || proto == CMS);
#endif
}

const std::vector<Key> &Sender::encryptToSelfCertificateCandidates(GpgME::Protocol proto) const
{
    if (proto == OpenPGP) {
        return d->pgpEncryptToSelfKeys;
    }
    if (proto == CMS) {
        return d->cmsEncryptToSelfKeys;
    }
    kleo_assert_fail(proto == OpenPGP || proto == CMS);
#if 0
    return
        proto == OpenPGP ? d->pgpEncryptToSelfKeys :
        proto == CMS     ? d->cmsEncryptToSelfKeys :
        // even though gcc warns about this line, it's completely ok, promise:
        kleo_assert_fail(proto == OpenPGP || proto == CMS);
#endif
}

void Sender::setResolvedSigningKey(const Key &key)
{
    if (key.isNull()) {
        return;
    }
    const Protocol proto = key.protocol();
    kleo_assert(proto == OpenPGP || proto == CMS);
    detach();
    d->signingKey[proto] = key;
    d->signingAmbiguous[proto] = false;
}

Key Sender::resolvedSigningKey(GpgME::Protocol proto) const
{
    kleo_assert(proto == OpenPGP || proto == CMS);
    return d->signingKey[proto];
}

void Sender::setResolvedEncryptionKey(const Key &key)
{
    if (key.isNull()) {
        return;
    }
    const Protocol proto = key.protocol();
    kleo_assert(proto == OpenPGP || proto == CMS);
    detach();
    if (proto == OpenPGP) {
        d->pgpEncryptionUid = key.userID(0);
    } else {
        d->cmsEncryptionKey = key;
    }
    d->encryptionAmbiguous[proto] = false;
}

Key Sender::resolvedEncryptionKey(GpgME::Protocol proto) const
{
    kleo_assert(proto == OpenPGP || proto == CMS);
    if (proto == OpenPGP) {
        return d->pgpEncryptionUid.parent();
    } else {
        return d->cmsEncryptionKey;
    }
}

void Sender::setResolvedOpenPGPEncryptionUserID(const UserID &uid)
{
    if (uid.isNull()) {
        return;
    }
    detach();
    d->pgpEncryptionUid = uid;
}

UserID Sender::resolvedOpenPGPEncryptionUserID() const
{
    return d->pgpEncryptionUid;
}
