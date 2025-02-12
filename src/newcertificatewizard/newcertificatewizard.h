/*
    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2008 Klarälvdalens Datakonsult AB

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#pragma once

#include <QWizard>

#include <gpgme++/global.h>

#include <memory>

class QDir;

namespace Kleo
{

namespace NewCertificateUi
{
class WizardPage;
}

class NewCertificateWizard : public QWizard
{
    Q_OBJECT
public:
    explicit NewCertificateWizard(QWidget *parent = nullptr);
    ~NewCertificateWizard() override;

    void setProtocol(GpgME::Protocol protocol);
    GpgME::Protocol protocol() const;

    enum Pages {
        EnterDetailsPageId,
        KeyCreationPageId,
        ResultPageId,

        NumPages
    };

protected:
    void showEvent(QShowEvent *event) override;

private:
    void restartAtEnterDetailsPage();
    QDir tmpDir() const;

private:
    class Private;
    const std::unique_ptr<Private> d;
    friend class ::Kleo::NewCertificateUi::WizardPage;
};

}
