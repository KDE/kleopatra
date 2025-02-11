/* -*- mode: c++; c-basic-offset:4 -*-
    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2008 Klarälvdalens Datakonsult AB

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#pragma once

#include <QWizard>

#include <QGpgME/SignKeyJob>

#include <gpgme++/key.h>

namespace Kleo
{

class CertifyWidget;

class CertifyCertificateDialog : public QDialog
{
    Q_OBJECT
public:
    explicit CertifyCertificateDialog(QWidget *parent = nullptr, Qt::WindowFlags f = {});
    ~CertifyCertificateDialog() override;

    /** Sets the certificate to certify for certifying user IDs of a single certificate. */
    void setCertificateToCertify(const GpgME::Key &key, const std::vector<GpgME::UserID> &uids = {});

    /** Sets the certificates to certify for bulk certification. */
    void setCertificatesToCertify(const std::vector<GpgME::Key> &keys);

    /** Set the optional group name when certifying the certificates of a certificate group. */
    void setGroupName(const QString &name);

    bool exportableCertificationSelected() const;

    bool trustSignatureSelected() const;
    QString trustSignatureDomain() const;

    void setSelectedUserIDs(const std::vector<GpgME::UserID> &uids);
    std::vector<GpgME::UserID> selectedUserIDs() const;

    GpgME::Key selectedSecretKey() const;

    bool sendToServer() const;

    QString tags() const;

    QDate expirationDate() const;

public Q_SLOTS:
    void accept() override;

private:
    CertifyWidget *mCertWidget = nullptr;
};

}
