/*
    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2007 Klarälvdalens Datakonsult AB

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#pragma once

#include <KMime/Types>
#include <gpgme++/key.h>

#include <KSharedConfig>

#include <memory>

class KConfig;

namespace GpgME
{
class Key;
}

namespace Kleo
{
namespace Crypto
{

class SigningPreferences
{
public:
    virtual ~SigningPreferences()
    {
    }
    virtual GpgME::Key preferredCertificate(GpgME::Protocol protocol) = 0;
    virtual void setPreferredCertificate(GpgME::Protocol protocol, const GpgME::Key &certificate) = 0;
};

class RecipientPreferences
{
public:
    virtual ~RecipientPreferences()
    {
    }
    virtual GpgME::Key preferredCertificate(const KMime::Types::Mailbox &recipient, GpgME::Protocol protocol) = 0;
    virtual void setPreferredCertificate(const KMime::Types::Mailbox &recipient, GpgME::Protocol protocol, const GpgME::Key &certificate) = 0;
};

class KConfigBasedRecipientPreferences : public RecipientPreferences
{
public:
    explicit KConfigBasedRecipientPreferences(const KSharedConfigPtr &config);
    ~KConfigBasedRecipientPreferences() override;
    GpgME::Key preferredCertificate(const KMime::Types::Mailbox &recipient, GpgME::Protocol protocol) override;
    void setPreferredCertificate(const KMime::Types::Mailbox &recipient, GpgME::Protocol protocol, const GpgME::Key &certificate) override;

private:
    Q_DISABLE_COPY(KConfigBasedRecipientPreferences)
    class Private;
    const std::unique_ptr<Private> d;
};

class KConfigBasedSigningPreferences : public SigningPreferences
{
public:
    explicit KConfigBasedSigningPreferences(const KSharedConfigPtr &config);
    ~KConfigBasedSigningPreferences() override;
    GpgME::Key preferredCertificate(GpgME::Protocol protocol) override;
    void setPreferredCertificate(GpgME::Protocol protocol, const GpgME::Key &certificate) override;

private:
    Q_DISABLE_COPY(KConfigBasedSigningPreferences)
    class Private;
    const std::unique_ptr<Private> d;
};
}
}
