/* -*- mode: c++; c-basic-offset:4 -*-
    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2008 Klarälvdalens Datakonsult AB
    SPDX-FileCopyrightText: 2019 g10code GmbH

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include <config-kleopatra.h>

#include "kleopatra_debug.h"

#include "certifycertificatedialog.h"

#include "certifywidget.h"

#include <Libkleo/Algorithm>
#include <Libkleo/Formatting>
#include <Libkleo/KeyHelpers>
#include <Libkleo/Stl_Util>

#include <KConfigGroup>
#include <KLocalizedString>
#include <KMessageBox>
#include <KSharedConfig>
#include <KStandardGuiItem>

#include <QDialogButtonBox>
#include <QKeyEvent>
#include <QPushButton>
#include <QVBoxLayout>

#include <gpg-error.h>

using namespace GpgME;
using namespace Kleo;

CertifyCertificateDialog::CertifyCertificateDialog(QWidget *p, Qt::WindowFlags f)
    : QDialog(p, f)
{
    setWindowTitle(i18nc("@title:window", "Certify Certificates"));
    setWindowFlags(windowFlags() & (~Qt::WindowContextHelpButtonHint));

    // Setup GUI
    auto mainLay = new QVBoxLayout(this);
    mCertWidget = new CertifyWidget(this);
    mainLay->addWidget(mCertWidget);

    auto buttonBox = new QDialogButtonBox{this};
    buttonBox->setStandardButtons(QDialogButtonBox::Cancel | QDialogButtonBox::Ok);
    const auto okButton = buttonBox->button(QDialogButtonBox::Ok);
    KGuiItem::assign(okButton, KStandardGuiItem::ok());
    okButton->setText(i18n("Certify"));
    KGuiItem::assign(buttonBox->button(QDialogButtonBox::Cancel), KStandardGuiItem::cancel());
    connect(buttonBox, &QDialogButtonBox::accepted, this, &CertifyCertificateDialog::accept);
    connect(buttonBox, &QDialogButtonBox::rejected, this, &QDialog::close);

    mainLay->addWidget(buttonBox);

    okButton->setEnabled(mCertWidget->isValid());
    connect(mCertWidget, &CertifyWidget::changed, this, [this, okButton]() {
        okButton->setEnabled(mCertWidget->isValid());
    });

    KConfigGroup cfgGroup(KSharedConfig::openStateConfig(), QStringLiteral("CertifyDialog"));
    const auto size = cfgGroup.readEntry("Size", QSize{640, 480});
    if (size.isValid()) {
        resize(size);
    }
}

CertifyCertificateDialog::~CertifyCertificateDialog()
{
    KConfigGroup cfgGroup(KSharedConfig::openStateConfig(), QStringLiteral("CertifyDialog"));
    cfgGroup.writeEntry("Size", size());
    cfgGroup.sync();
}

void CertifyCertificateDialog::setCertificateToCertify(const Key &key, const std::vector<GpgME::UserID> &uids)
{
    Q_ASSERT(std::ranges::all_of(uids, [key](const auto &uid) {
        return Kleo::userIDBelongsToKey(uid, key);
    }));
    setWindowTitle(i18nc("@title:window arg is name, email of certificate holder", "Certify Certificate: %1", Formatting::prettyName(key)));
    mCertWidget->setCertificate(key, uids);
}

void CertifyCertificateDialog::setCertificatesToCertify(const std::vector<GpgME::Key> &keys)
{
    mCertWidget->setCertificates(keys);
}

void CertifyCertificateDialog::setGroupName(const QString &name)
{
    setWindowTitle(i18nc("@title:window Certify Certificate Group <group name>", "Certify Certificate Group %1", name));
}

bool CertifyCertificateDialog::exportableCertificationSelected() const
{
    return mCertWidget->exportableSelected();
}

bool CertifyCertificateDialog::trustSignatureSelected() const
{
    return mCertWidget->trustSignatureSelected();
}

QString CertifyCertificateDialog::trustSignatureDomain() const
{
    return mCertWidget->trustSignatureDomain();
}

Key CertifyCertificateDialog::selectedSecretKey() const
{
    return mCertWidget->secKey();
}

bool CertifyCertificateDialog::sendToServer() const
{
    return mCertWidget->publishSelected();
}

void CertifyCertificateDialog::setSelectedUserIDs(const std::vector<UserID> &uids)
{
    mCertWidget->selectUserIDs(uids);
}

std::vector<GpgME::UserID> CertifyCertificateDialog::selectedUserIDs() const
{
    return mCertWidget->selectedUserIDs();
}

QString CertifyCertificateDialog::tags() const
{
    return mCertWidget->tags();
}

QDate CertifyCertificateDialog::expirationDate() const
{
    return mCertWidget->expirationDate();
}

void CertifyCertificateDialog::accept()
{
    if (!mCertWidget->isValid()) {
        return;
    }

    mCertWidget->saveState();

    QDialog::accept();
}

#include "moc_certifycertificatedialog.cpp"
