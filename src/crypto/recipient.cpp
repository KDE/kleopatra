/*
    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2009 Klarälvdalens Datakonsult AB

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include <config-kleopatra.h>

#include "recipient.h"

#include <Libkleo/KeyCache>
#include <Libkleo/Predicates>
#include <Libkleo/Stl_Util>

#include <utils/cached.h>
#include <utils/kleo_assert.h>

#include <KMime/Types>

#include <gpgme++/key.h>

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

class Recipient::Private
{
    friend class ::Kleo::Crypto::Recipient;

public:
    explicit Private(const Mailbox &mb)
        : mailbox(mb)
    {
        // ### also fill up to a certain number of keys with those
        // ### that don't match, for the case where there's a low
        // ### total number of keys
        const std::vector<Key> encrypt = KeyCache::instance()->findEncryptionKeysByMailbox(mb.addrSpec().asString());
        kdtools::separate_if(encrypt.cbegin(),
                             encrypt.cend(),
                             std::back_inserter(pgpEncryptionKeys),
                             std::back_inserter(cmsEncryptionKeys),
                             [](const Key &key) {
                                 return key.protocol() == OpenPGP;
                             });
    }

private:
    const Mailbox mailbox;
    std::vector<Key> pgpEncryptionKeys, cmsEncryptionKeys;
    Key cmsEncryptionKey;
    UserID pgpEncryptionUid;
    cached<bool> encryptionAmbiguous[2];
};

Recipient::Recipient(const Mailbox &mb)
    : d(new Private(mb))
{
}

void Recipient::detach()
{
    if (d && d.use_count() != 1) {
        d.reset(new Private(*d));
    }
}

bool Recipient::deepEquals(const Recipient &other) const
{
    static const _detail::ByFingerprint<std::equal_to> compare = {};
    return mailbox() == other.mailbox() //
        && compare(d->cmsEncryptionKey, other.d->cmsEncryptionKey) //
        && compare(d->pgpEncryptionUid.parent(), other.d->pgpEncryptionUid.parent()) //
        && strcmp(d->pgpEncryptionUid.id(), other.d->pgpEncryptionUid.id()) //
        && std::equal(d->pgpEncryptionKeys.cbegin(), d->pgpEncryptionKeys.cend(), other.d->pgpEncryptionKeys.cbegin(), compare)
        && std::equal(d->cmsEncryptionKeys.cbegin(), d->pgpEncryptionKeys.cend(), other.d->cmsEncryptionKeys.cbegin(), compare);
}

bool Recipient::isEncryptionAmbiguous(GpgME::Protocol proto) const
{
    if (d->encryptionAmbiguous[proto].dirty()) {
        d->encryptionAmbiguous[proto] = determine_ambiguous(d->mailbox, encryptionCertificateCandidates(proto));
    }
    return d->encryptionAmbiguous[proto];
}

const Mailbox &Recipient::mailbox() const
{
    return d->mailbox;
}

const std::vector<Key> &Recipient::encryptionCertificateCandidates(GpgME::Protocol proto) const
{
    if (proto == OpenPGP) {
        return d->pgpEncryptionKeys;
    }
    if (proto == CMS) {
        return d->cmsEncryptionKeys;
    }
    kleo_assert_fail(proto == OpenPGP || proto == CMS);
#if 0
    return
        proto == OpenPGP ? d->pgpEncryptionKeys :
        proto == CMS     ? d->cmsEncryptionKeys :
        // even though gcc warns about this line, it's completely ok, promise:
        kleo_assert_fail(proto == OpenPGP || proto == CMS);
#endif
}

void Recipient::setResolvedEncryptionKey(const Key &key)
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

Key Recipient::resolvedEncryptionKey(GpgME::Protocol proto) const
{
    kleo_assert(proto == OpenPGP || proto == CMS);
    if (proto == OpenPGP) {
        return d->pgpEncryptionUid.parent();
    } else {
        return d->cmsEncryptionKey;
    }
}

void Recipient::setResolvedOpenPGPEncryptionUserID(const UserID &uid)
{
    if (uid.isNull()) {
        return;
    }
    detach();
    d->pgpEncryptionUid = uid;
}

UserID Recipient::resolvedOpenPGPEncryptionUserID() const
{
    return d->pgpEncryptionUid;
}
