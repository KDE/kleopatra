/* -*- mode: c++; c-basic-offset:4 -*-
    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2007 Klarälvdalens Datakonsult AB

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#pragma once

#include <crypto/gui/wizardpage.h>

#include <KMime/Types>
#include <gpgme++/global.h>

#include <memory>
#include <set>
#include <vector>

namespace GpgME
{
class Key;
}

namespace Kleo
{
namespace Crypto
{

class SigningPreferences;

namespace Gui
{
class SignerResolvePage : public WizardPage
{
    Q_OBJECT
public:
    explicit SignerResolvePage(QWidget *parent = nullptr, Qt::WindowFlags f = {});
    ~SignerResolvePage() override;

    void setSignersAndCandidates(const std::vector<KMime::Types::Mailbox> &signers, const std::vector<std::vector<GpgME::Key>> &keys);

    std::vector<GpgME::Key> resolvedSigners() const;
    std::vector<GpgME::Key> signingCertificates(GpgME::Protocol protocol = GpgME::UnknownProtocol) const;

    bool isComplete() const override;

    bool encryptionSelected() const;
    void setEncryptionSelected(bool selected);

    bool signingSelected() const;
    void setSigningSelected(bool selected);

    bool isEncryptionUserMutable() const;
    void setEncryptionUserMutable(bool ismutable);

    bool isSigningUserMutable() const;
    void setSigningUserMutable(bool ismutable);

    bool isAsciiArmorEnabled() const;
    void setAsciiArmorEnabled(bool enabled);

    void setPresetProtocol(GpgME::Protocol protocol);
    void setPresetProtocols(const std::vector<GpgME::Protocol> &protocols);

    std::set<GpgME::Protocol> selectedProtocols() const;

    std::set<GpgME::Protocol> selectedProtocolsWithoutSigningCertificate() const;

    void setMultipleProtocolsAllowed(bool allowed);
    bool multipleProtocolsAllowed() const;

    void setProtocolSelectionUserMutable(bool ismutable);
    bool protocolSelectionUserMutable() const;

    enum Operation {
        SignAndEncrypt = 0,
        SignOnly,
        EncryptOnly,
    };

    Operation operation() const;

    class Validator
    {
    public:
        virtual ~Validator()
        {
        }
        virtual bool isComplete() const = 0;
        virtual QString explanation() const = 0;
        /**
         * returns a custom window title, or a null string if no custom
         * title is required.
         * (use this if the title needs dynamic adaption
         * depending on the user's selection)
         */
        virtual QString customWindowTitle() const = 0;
    };

    void setValidator(const std::shared_ptr<Validator> &);
    std::shared_ptr<Validator> validator() const;

    void setSigningPreferences(const std::shared_ptr<SigningPreferences> &prefs);
    std::shared_ptr<SigningPreferences> signingPreferences() const;

private:
    bool onNext() override;

private:
    class Private;
    const std::unique_ptr<Private> d;

    Q_PRIVATE_SLOT(d, void operationButtonClicked(int))
    Q_PRIVATE_SLOT(d, void selectCertificates())
    Q_PRIVATE_SLOT(d, void updateUi())
};
}
}
}
