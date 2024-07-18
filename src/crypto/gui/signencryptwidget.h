/*  crypto/gui/signencryptwidget.h

    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2016 Bundesamt für Sicherheit in der Informationstechnik
    SPDX-FileContributor: Intevation GmbH

    SPDX-License-Identifier: GPL-2.0-or-later
*/
#pragma once

#include "dialogs/certificateselectiondialog.h"

#include <QVector>
#include <QWidget>

#include <gpgme++/global.h>

#include <Libkleo/UserIDSelectionCombo>

#include <memory>

namespace GpgME
{
class Key;
}

namespace Kleo
{
class CertificateLineEdit;
class KeyGroup;

class SignEncryptWidget : public QWidget
{
    Q_OBJECT
public:
    enum Operation { NoOperation = 0x00, Sign = 0x01, Encrypt = 0x02, SignAndEncrypt = Sign | Encrypt };
    Q_DECLARE_FLAGS(Operations, Operation)

    /** If cmsSigEncExclusive is true CMS operations can be
     * done only either as sign or as encrypt */
    explicit SignEncryptWidget(QWidget *parent = nullptr, bool cmsSigEncExclusive = false);

    ~SignEncryptWidget() override;

    /** Overwrite default text with custom text, e.g. with a character marked
     *  as shortcut key. */
    void setSignAsText(const QString &text);
    void setEncryptForMeText(const QString &text);
    void setEncryptForOthersText(const QString &text);
    void setEncryptWithPasswordText(const QString &text);

    /** Returns the list of recipients selected in the dialog
     * or an empty list if encryption is disabled */
    std::vector<GpgME::Key> recipients() const;

    /** Returns the selected signing key or a null key if signing
     * is disabled. */
    GpgME::UserID signUserId() const;

    /** Returns the selected encrypt to self key or a null key if
     * encrypt to self is disabled. */
    GpgME::UserID selfUserId() const;

    /** Returns the operation based on the current selection. */
    Operations currentOp() const;

    /** Whether or not symmetric encryption should also be used. */
    bool encryptSymmetric() const;

    /** Save the currently selected signing and encrypt to self keys. */
    void saveOwnKeys() const;

    /** Return whether or not all keys involved in the operation are
        compliant with CO_DE_VS, and all keys are valid (i.e. all
        userIDs have Validity >= Full).  */
    bool isDeVsAndValid() const;

    /** Set whether or not signing group should be checked */
    void setSigningChecked(bool value);

    /** Set whether or not encryption group should be checked */
    void setEncryptionChecked(bool value);

    /** Filter for a specific protocol. Use UnknownProtocol for both
     * S/MIME and OpenPGP */
    void setProtocol(GpgME::Protocol protocol);

    /** Add a recipient with the key key */
    void addRecipient(const GpgME::Key &key);

    /** Add a group of recipients */
    void addRecipient(const Kleo::KeyGroup &group);

    /** Add a placehoder for an unknown key */
    void addUnknownRecipient(const char *keyId);

    /** Remove all Recipients added by keyId or by key. */
    void clearAddedRecipients();

    /** Remove a Recipient key */
    void removeRecipient(const GpgME::Key &key);

    /** Remove a recipient group */
    void removeRecipient(const Kleo::KeyGroup &group);

    /** Returns true if all required information has been entered. */
    bool isComplete() const;

    /** Returns true if all recipients have been resolved. Otherwise, shows
        an error message and returns false. */
    bool validate();

protected Q_SLOTS:
    void updateOp();
    void recipientsChanged();
    void certificateSelectionRequested(CertificateLineEdit *w);
    void ownCertificateSelectionRequested(Kleo::Dialogs::CertificateSelectionDialog::Options options, UserIDSelectionCombo *combo);

protected:
    void loadKeys();

Q_SIGNALS:
    /* Emitted when the certificate selection changed the operation
     * with that selection. e.g. "Sign" or "Sign/Encrypt".
     * If no crypto operation is selected this returns a null string. */
    void operationChanged(Operations op);

    /* Emitted when the certificate selection might be changed. */
    void keysChanged();

private:
    class Private;
    const std::unique_ptr<Private> d;
};
} // namespace Kleo

Q_DECLARE_OPERATORS_FOR_FLAGS(Kleo::SignEncryptWidget::Operations)
