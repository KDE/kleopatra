/* -*- mode: c++; c-basic-offset:4 -*-
    newcertificatewizard/wizardpage_p.h

    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2008 Klarälvdalens Datakonsult AB

    SPDX-FileCopyrightText: 2016, 2017 Bundesamt für Sicherheit in der Informationstechnik
    SPDX-FileContributor: Intevation GmbH

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#pragma once

#include "newcertificatewizard.h"

#include "utils/metatypes_for_gpgmepp_key.h"

#include <QDate>
#include <QDir>
#include <QVariant>
#include <QWizardPage>

#include <gpgme++/key.h>

namespace Kleo
{
namespace NewCertificateUi
{

class WizardPage : public QWizardPage
{
    Q_OBJECT
protected:
    explicit WizardPage(QWidget *parent = nullptr)
        : QWizardPage(parent)
    {
    }

    NewCertificateWizard *wizard() const
    {
        Q_ASSERT(static_cast<NewCertificateWizard *>(QWizardPage::wizard()) == qobject_cast<NewCertificateWizard *>(QWizardPage::wizard()));
        return static_cast<NewCertificateWizard *>(QWizardPage::wizard());
    }

    void restartAtEnterDetailsPage()
    {
        wizard()->restartAtEnterDetailsPage();
    }

    QDir tmpDir() const
    {
        return wizard()->tmpDir();
    }

protected:
#define FIELD(type, name)                                                                                                                                      \
    type name() const {return field(QStringLiteral(#name)).value<type>();                                                                                      \
    }
    FIELD(bool, signingAllowed)
    FIELD(bool, encryptionAllowed)

    FIELD(QString, name)
    FIELD(QString, email)
    FIELD(QString, dn)
    FIELD(bool, protectedKey)

    FIELD(GpgME::Subkey::PubkeyAlgo, keyType)
    FIELD(int, keyStrength)

    FIELD(QStringList, additionalEMailAddresses)
    FIELD(QStringList, dnsNames)
    FIELD(QStringList, uris)

    FIELD(QString, url)
    FIELD(QString, error)
    FIELD(QString, result)
    FIELD(QString, fingerprint)
#undef FIELD
};

} // namespace NewCertificateUi
} // namespace Kleo
