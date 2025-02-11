/* -*- mode: c++; c-basic-offset:4 -*-
    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2009 Klarälvdalens Datakonsult AB

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#pragma once

#include <gpgme++/global.h>

#include <memory>
#include <vector>

namespace KMime
{
namespace Types
{
class Mailbox;
}
}

namespace GpgME
{
class Key;
class UserID;
}

namespace Kleo
{
namespace Crypto
{

class Recipient
{
public:
    Recipient()
        : d()
    {
    }
    explicit Recipient(const KMime::Types::Mailbox &mailbox);

    void swap(Recipient &other)
    {
        d.swap(other.d);
    }

    bool isNull() const
    {
        return !d;
    }

    bool isEncryptionAmbiguous(GpgME::Protocol protocol) const;

    const KMime::Types::Mailbox &mailbox() const;

    const std::vector<GpgME::Key> &encryptionCertificateCandidates(GpgME::Protocol proto) const;

    void setResolvedEncryptionKey(const GpgME::Key &key);
    GpgME::Key resolvedEncryptionKey(GpgME::Protocol proto) const;

    void setResolvedOpenPGPEncryptionUserID(const GpgME::UserID &uid);
    GpgME::UserID resolvedOpenPGPEncryptionUserID() const;

    friend inline bool operator==(const Recipient &lhs, const Recipient &rhs)
    {
        return rhs.d == lhs.d || lhs.deepEquals(rhs);
    }

private:
    void detach();
    bool deepEquals(const Recipient &other) const;

private:
    class Private;
    std::shared_ptr<Private> d;
};

inline bool operator!=(const Recipient &lhs, const Recipient &rhs)
{
    return !operator==(lhs, rhs);
}

} // namespace Crypto
} // namespace Kleo
