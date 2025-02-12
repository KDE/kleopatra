/*
    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2007, 2009 Klarälvdalens Datakonsult AB

    SPDX-License-Identifier: GPL-2.0-or-later
*/
#pragma once

#include <QWidget>

#include <gpgme++/global.h>

#include <memory>
#include <set>

template<typename K, typename U>
class QMap;

namespace GpgME
{
class Key;
}

namespace Kleo
{
struct CertificatePair;

namespace Crypto
{
namespace Gui
{

class SigningCertificateSelectionWidget : public QWidget
{
    Q_OBJECT
public:
    explicit SigningCertificateSelectionWidget(QWidget *parent = nullptr, Qt::WindowFlags f = {});
    ~SigningCertificateSelectionWidget() override;

    void setAllowedProtocols(const std::set<GpgME::Protocol> &allowedProtocols);
    void setAllowedProtocols(bool pgp, bool cms);
    void setSelectedCertificates(const CertificatePair &certificates);
    void setSelectedCertificates(const GpgME::Key &pgp, const GpgME::Key &cms);
    CertificatePair selectedCertificates() const;

    bool rememberAsDefault() const;

private:
    class Private;
    const std::unique_ptr<Private> d;
};

}
}
}
