/* -*- mode: c++; c-basic-offset:4 -*-
    dialogs/certificateselectiondialog.h

    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2008 Klarälvdalens Datakonsult AB

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
class UserID;
}

namespace Kleo
{

class KeyFilter;
class KeyGroup;

namespace Dialogs
{

class CertificateSelectionDialog : public QDialog
{
    Q_OBJECT
    Q_FLAGS(Options)
public:
    enum Option {
        // clang-format off
        SingleSelection = 0x00,
        MultiSelection  = 0x01,

        SignOnly        = 0x02,
        EncryptOnly     = 0x04,
        AnyCertificate  = 0x06,

        OpenPGPFormat   = 0x08,
        CMSFormat       = 0x10,
        AnyFormat       = 0x18,

        Certificates    = 0x00,
        SecretKeys      = 0x20,

        IncludeGroups   = 0x40,

        OptionMask
        // clang-format on
    };
    Q_DECLARE_FLAGS(Options, Option)

    static Option optionsFromProtocol(GpgME::Protocol proto);

    explicit CertificateSelectionDialog(QWidget *parent = nullptr);
    ~CertificateSelectionDialog() override;

    void setCustomLabelText(const QString &text);
    QString customLabelText() const;

    void setOptions(Options options);
    Options options() const;

    void selectCertificates(const std::vector<GpgME::Key> &certs);
    void selectCertificate(const GpgME::Key &key);

    std::vector<GpgME::Key> selectedCertificates() const;
    GpgME::Key selectedCertificate() const;

    void selectGroups(const std::vector<Kleo::KeyGroup> &groups);
    std::vector<Kleo::KeyGroup> selectedGroups() const;

    std::vector<GpgME::UserID> selectedUserIDs() const;

    static void filterAllowedKeys(std::vector<GpgME::Key> &keys, int options);

    void addCustomKeyFilter(const std::shared_ptr<Kleo::KeyFilter> &filter);

public Q_SLOTS:
    void setStringFilter(const QString &text);
    void setKeyFilter(const std::shared_ptr<Kleo::KeyFilter> &filter);
    void accept() override;

protected:
    void hideEvent(QHideEvent *) override;

private:
    class Private;
    const std::unique_ptr<Private> d;
};

}
}

Q_DECLARE_OPERATORS_FOR_FLAGS(Kleo::Dialogs::CertificateSelectionDialog::Options)
