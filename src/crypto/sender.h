/*
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

class Sender
{
public:
    Sender()
        : d()
    {
    }
    explicit Sender(const KMime::Types::Mailbox &mailbox);

    void swap(Sender &other)
    {
        d.swap(other.d);
    }

    bool isNull() const
    {
        return !d;
    }

    bool isSigningAmbiguous(GpgME::Protocol proto) const;
    bool isEncryptionAmbiguous(GpgME::Protocol proto) const;

    const KMime::Types::Mailbox &mailbox() const;

    const std::vector<GpgME::Key> &signingCertificateCandidates(GpgME::Protocol proto) const;
    const std::vector<GpgME::Key> &encryptToSelfCertificateCandidates(GpgME::Protocol proto) const;

    void setResolvedSigningKey(const GpgME::Key &key);
    GpgME::Key resolvedSigningKey(GpgME::Protocol proto) const;

    void setResolvedEncryptionKey(const GpgME::Key &key);
    GpgME::Key resolvedEncryptionKey(GpgME::Protocol proto) const;

    void setResolvedOpenPGPEncryptionUserID(const GpgME::UserID &uid);
    GpgME::UserID resolvedOpenPGPEncryptionUserID() const;

    friend inline bool operator==(const Sender &lhs, const Sender &rhs)
    {
        return rhs.d == lhs.d || lhs.deepEquals(rhs);
    }

private:
    void detach();
    bool deepEquals(const Sender &other) const;

private:
    class Private;
    std::shared_ptr<Private> d;
};

inline bool operator!=(const Sender &lhs, const Sender &rhs)
{
    return !operator==(lhs, rhs);
}

} // namespace Crypto
} // namespace Kleo
