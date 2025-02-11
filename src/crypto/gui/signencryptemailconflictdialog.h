/* -*- mode: c++; c-basic-offset:4 -*-
    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2009 Klarälvdalens Datakonsult AB

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#pragma once

#include <QDialog>

#include <gpgme++/global.h>

#include <memory>
#include <vector>

namespace GpgME
{
class Key;
}

namespace Kleo
{
namespace Crypto
{
class Sender;
class Recipient;
}
}

namespace Kleo
{
namespace Crypto
{
namespace Gui
{

class SignEncryptEMailConflictDialog : public QDialog
{
    Q_OBJECT
public:
    explicit SignEncryptEMailConflictDialog(QWidget *parent = nullptr);
    ~SignEncryptEMailConflictDialog() override;

    // Inputs

    void setPresetProtocol(GpgME::Protocol proto);
    void setSubject(const QString &subject);

    void setSenders(const std::vector<Sender> &senders);
    void setRecipients(const std::vector<Recipient> &recipients);

    void setSign(bool on);
    void setEncrypt(bool on);

    void setQuickMode(bool on);

    // To wrap up inputs:
    void pickProtocol();
    void setConflict(bool conflict);

    // Intermediate

    bool isComplete() const;

    // Outputs

    GpgME::Protocol selectedProtocol() const;
    std::vector<GpgME::Key> resolvedSigningKeys() const;
    std::vector<GpgME::Key> resolvedEncryptionKeys() const;

    bool isQuickMode() const;

private:
    Q_PRIVATE_SLOT(d, void slotCompleteChanged())
    Q_PRIVATE_SLOT(d, void slotShowAllRecipientsToggled(bool))
    Q_PRIVATE_SLOT(d, void slotProtocolChanged())
    Q_PRIVATE_SLOT(d, void slotCertificateSelectionDialogRequested())
    class Private;
    const std::unique_ptr<Private> d;
};

}
}
}
