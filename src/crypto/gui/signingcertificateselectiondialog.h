/*
    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2007 Klarälvdalens Datakonsult AB

    SPDX-License-Identifier: GPL-2.0-or-later
*/
#pragma once

#include <QDialog>

#include <gpgme++/key.h>

#include <set>

template<typename K, typename U>
class QMap;

namespace Kleo
{
struct CertificatePair;

namespace Crypto
{
namespace Gui
{

class SigningCertificateSelectionWidget;

class SigningCertificateSelectionDialog : public QDialog
{
    Q_OBJECT
public:
    explicit SigningCertificateSelectionDialog(QWidget *parent = nullptr);
    ~SigningCertificateSelectionDialog() override;

    void setAllowedProtocols(const std::set<GpgME::Protocol> &allowedProtocols);
    void setSelectedCertificates(const CertificatePair &certificates);
    [[nodiscard]] CertificatePair selectedCertificates() const;

    [[nodiscard]] bool rememberAsDefault() const;

private:
    SigningCertificateSelectionWidget *const widget;
};

}
}
}
