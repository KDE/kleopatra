/* -*- mode: c++; c-basic-offset:4 -*-
    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2007 Klarälvdalens Datakonsult AB

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#pragma once

#include <crypto/gui/wizardpage.h>

#include <gpgme++/global.h>

#include <memory>
#include <vector>

namespace GpgME
{
class Key;
}

namespace KMime
{
namespace Types
{
class Mailbox;
}
}

namespace Kleo
{
namespace Crypto
{

class RecipientPreferences;

namespace Gui
{

class ResolveRecipientsPage : public WizardPage
{
    Q_OBJECT
public:
    explicit ResolveRecipientsPage(QWidget *parent = nullptr);
    ~ResolveRecipientsPage() override;

    bool isComplete() const override;

    /**
     * The protocol selected by the user (which is chosen by
     * the user in case none was preset)
     */
    GpgME::Protocol selectedProtocol() const;

    /**
     * the protocol set before the dialog is shown. Defaults to
     * GpgME::UnknownProtocol */
    GpgME::Protocol presetProtocol() const;
    void setPresetProtocol(GpgME::Protocol protocol);

    bool multipleProtocolsAllowed() const;
    void setMultipleProtocolsAllowed(bool allowed);

    /** if true, the user is allowed to remove/add recipients via the UI.
     * Defaults to @p false.
     */
    bool recipientsUserMutable() const;
    void setRecipientsUserMutable(bool isMutable);

    void setAdditionalRecipientsInfo(const std::vector<GpgME::Key> &recipients);

    std::vector<GpgME::Key> resolvedCertificates() const;

    std::shared_ptr<RecipientPreferences> recipientPreferences() const;
    void setRecipientPreferences(const std::shared_ptr<RecipientPreferences> &prefs);

Q_SIGNALS:
    void selectedProtocolChanged();

private:
    bool onNext() override;

private:
    class Private;
    const std::unique_ptr<Private> d;
    Q_PRIVATE_SLOT(d, void selectionChanged())
    Q_PRIVATE_SLOT(d, void protocolSelected(int))
    Q_PRIVATE_SLOT(d, void addRecipient())
    Q_PRIVATE_SLOT(d, void removeSelectedEntries())
    Q_PRIVATE_SLOT(d, void completeChangedInternal())
    class ListWidget;
    class ItemWidget;
};

}
}
}
