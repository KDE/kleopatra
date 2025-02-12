/*
    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2020 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include "createcsrforcardkeydialog.h"

#include "certificatedetailsinputwidget.h"

#include <KConfigGroup>
#include <KSharedConfig>

#include <QDialogButtonBox>
#include <QPushButton>
#include <QVBoxLayout>

using namespace Kleo;
using namespace Kleo::Dialogs;

class CreateCSRForCardKeyDialog::Private
{
    friend class ::Kleo::Dialogs::CreateCSRForCardKeyDialog;
    CreateCSRForCardKeyDialog *const q;

    struct {
        CertificateDetailsInputWidget *detailsWidget = nullptr;
        QDialogButtonBox *buttonBox = nullptr;
    } ui;

public:
    Private(CreateCSRForCardKeyDialog *qq)
        : q(qq)
    {
        auto mainLayout = new QVBoxLayout(q);

        ui.detailsWidget = new CertificateDetailsInputWidget();
        connect(ui.detailsWidget, &CertificateDetailsInputWidget::validityChanged, q, [this](bool valid) {
            onValidityChanged(valid);
        });

        ui.buttonBox = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel);
        connect(ui.buttonBox, &QDialogButtonBox::accepted, q, &QDialog::accept);
        connect(ui.buttonBox, &QDialogButtonBox::rejected, q, &QDialog::reject);

        mainLayout->addWidget(ui.detailsWidget);
        mainLayout->addWidget(ui.buttonBox);

        // increase default width by 50 % to get more space for line edits
        const QSize sizeHint = q->sizeHint();
        const QSize defaultSize = QSize(sizeHint.width() * 15 / 10, sizeHint.height());
        restoreGeometry(defaultSize);
    }

    ~Private()
    {
        saveGeometry();
    }

    void onValidityChanged(bool valid)
    {
        ui.buttonBox->button(QDialogButtonBox::Ok)->setEnabled(valid);
    }

private:
    void saveGeometry()
    {
        KConfigGroup cfgGroup(KSharedConfig::openStateConfig(), QStringLiteral("CreateCSRForCardKeyDialog"));
        cfgGroup.writeEntry("Size", q->size());
        cfgGroup.sync();
    }

    void restoreGeometry(const QSize &defaultSize)
    {
        KConfigGroup cfgGroup(KSharedConfig::openStateConfig(), QStringLiteral("CreateCSRForCardKeyDialog"));
        const QSize size = cfgGroup.readEntry("Size", defaultSize);
        if (size.isValid()) {
            q->resize(size);
        }
    }
};

CreateCSRForCardKeyDialog::CreateCSRForCardKeyDialog(QWidget *parent)
    : QDialog(parent)
    , d(new Private(this))
{
}

CreateCSRForCardKeyDialog::~CreateCSRForCardKeyDialog()
{
}

void CreateCSRForCardKeyDialog::setName(const QString &name)
{
    d->ui.detailsWidget->setName(name);
}

void CreateCSRForCardKeyDialog::setEmail(const QString &email)
{
    d->ui.detailsWidget->setEmail(email);
}

QString CreateCSRForCardKeyDialog::email() const
{
    return d->ui.detailsWidget->email();
}

QString CreateCSRForCardKeyDialog::dn() const
{
    return d->ui.detailsWidget->dn();
}

#include "moc_createcsrforcardkeydialog.cpp"
