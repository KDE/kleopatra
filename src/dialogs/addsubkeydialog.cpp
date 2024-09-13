/* -*- mode: c++; c-basic-offset:4 -*-

    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2008 Klarälvdalens Datakonsult AB
    SPDX-FileCopyrightText: 2021-2023 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>
    SPDX-FileContributor: Tobias Fella <tobias.fella@gnupg.com>

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include "addsubkeydialog.h"

#include "utils/gui-helper.h"
#include "utils/scrollarea.h"

#include <Libkleo/Compat>
#include <Libkleo/Compliance>
#include <Libkleo/Expiration>
#include <Libkleo/Formatting>
#include <Libkleo/GnuPG>

#include <KConfigGroup>
#include <KDateComboBox>
#include <KLocalizedString>
#include <KMessageBox>
#include <KSharedConfig>
#include <KStandardGuiItem>

#include <QGpgME/CryptoConfig>
#include <QGpgME/Protocol>

#include <QCheckBox>
#include <QDate>
#include <QDialogButtonBox>
#include <QFormLayout>
#include <QGroupBox>
#include <QHBoxLayout>
#include <QLabel>
#include <QPushButton>
#include <QRadioButton>
#include <QVBoxLayout>

#include <gpgme++/key.h>

using namespace Kleo;
using namespace Kleo::Dialogs;
using namespace GpgME;

class AddSubkeyDialog::Private
{
    AddSubkeyDialog *const q;

public:
    Private(AddSubkeyDialog *qq)
        : q{qq}
        , ui{qq}
    {
    }

    struct UI {
        QComboBox *keyAlgoCB = nullptr;

        QRadioButton *signingCB = nullptr;
        QRadioButton *encryptionCB = nullptr;
        QRadioButton *authenticationCB = nullptr;

        QCheckBox *expiryCB = nullptr;
        KDateComboBox *expiryDE = nullptr;

        QLabel *primaryKeyExpiration = nullptr;
        QDialogButtonBox *buttonBox = nullptr;

        UI(QDialog *parent)
        {
            parent->setWindowTitle(i18nc("@title:window", "Advanced Settings"));

            const auto mainLayout = new QVBoxLayout{parent};

            const auto scrollArea = new ScrollArea{parent};
            {
                scrollArea->setFocusPolicy(Qt::NoFocus);
                scrollArea->setFrameStyle(QFrame::NoFrame);
                scrollArea->setBackgroundRole(parent->backgroundRole());
                scrollArea->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
                scrollArea->setSizeAdjustPolicy(QScrollArea::AdjustToContents);
                const auto scrollLayout = qobject_cast<QVBoxLayout *>(scrollArea->widget()->layout());

                {
                    const auto groupBox = new QGroupBox{i18nc("@title:group", "Key Material"), scrollArea};

                    const auto formLayout = new QFormLayout(groupBox);

                    keyAlgoCB = new QComboBox(groupBox);
                    formLayout->addRow(i18n("Algorithm:"), keyAlgoCB);

                    scrollLayout->addWidget(groupBox);
                }
                {
                    const auto groupBox = new QGroupBox{i18nc("@title:group", "Certificate Usage"), scrollArea};
                    const auto usageLayout = new QVBoxLayout;

                    signingCB = new QRadioButton{i18nc("@option:check", "Signing"), groupBox};
                    usageLayout->addWidget(signingCB);

                    encryptionCB = new QRadioButton{i18nc("@option:check", "Encryption"), groupBox};
                    encryptionCB->setChecked(true);
                    usageLayout->addWidget(encryptionCB);

                    authenticationCB = new QRadioButton{i18nc("@option:check", "Authentication"), groupBox};
                    usageLayout->addWidget(authenticationCB);

                    {
                        const auto hbox = new QHBoxLayout;

                        expiryCB = new QCheckBox{i18nc("@option:check", "Valid until:"), groupBox};
                        expiryCB->setChecked(true);
                        hbox->addWidget(expiryCB);

                        expiryDE = new KDateComboBox(groupBox);
                        hbox->addWidget(expiryDE, 1);
                        connect(expiryCB, &QCheckBox::toggled, expiryDE, &KDateComboBox::setEnabled);

                        usageLayout->addLayout(hbox);
                    }
                    primaryKeyExpiration = new QLabel(groupBox);
                    primaryKeyExpiration->setVisible(false);
                    usageLayout->addWidget(primaryKeyExpiration);

                    groupBox->setLayout(usageLayout);
                    scrollLayout->addWidget(groupBox);
                }

                scrollLayout->addStretch(1);
            }

            mainLayout->addWidget(scrollArea);

            buttonBox = new QDialogButtonBox{parent};
            buttonBox->setStandardButtons(QDialogButtonBox::Cancel | QDialogButtonBox::Ok);

            mainLayout->addWidget(buttonBox);
        }
    } ui;
};

AddSubkeyDialog::AddSubkeyDialog(const GpgME::Key &parent, QWidget *p)
    : QDialog{p}
    , d{new Private{this}}
{
    setWindowTitle(i18nc("@title:window", "Add Subkey"));
    d->ui.expiryCB->setEnabled(unlimitedValidityIsAllowed());

    if (!parent.subkey(0).neverExpires()) {
        d->ui.expiryDE->setMaximumDate(Kleo::Formatting::expirationDate(parent));
        d->ui.primaryKeyExpiration->setText(i18n("Expiration of primary key: %1", Kleo::Formatting::expirationDateString(parent)));
        d->ui.primaryKeyExpiration->setVisible(true);
    }
    d->ui.expiryDE->setMinimumDate(QDate::currentDate());

    loadDefaults();

    connect(d->ui.buttonBox, &QDialogButtonBox::accepted, this, &AddSubkeyDialog::accept);
    connect(d->ui.buttonBox, &QDialogButtonBox::rejected, this, &QDialog::reject);
}

AddSubkeyDialog::~AddSubkeyDialog() = default;

bool AddSubkeyDialog::unlimitedValidityIsAllowed() const
{
    return !Expiration::maximumExpirationDate().isValid();
}

void AddSubkeyDialog::setKeyType(const QString &algorithm)
{
    const auto index = d->ui.keyAlgoCB->findData(algorithm);
    if (index != -1) {
        d->ui.keyAlgoCB->setCurrentIndex(index);
    }
}

void AddSubkeyDialog::loadDefaults()
{
    setExpiryDate(defaultExpirationDate(unlimitedValidityIsAllowed() ? Expiration::ExpirationOnUnlimitedValidity::NoExpiration
                                                                     : Expiration::ExpirationOnUnlimitedValidity::InternalDefaultExpiration));
    loadAlgorithms();
    loadDefaultKeyType();
}

void AddSubkeyDialog::replaceEntry(const QString &before, const QString &after)
{
    const auto currentIndex = d->ui.keyAlgoCB->currentIndex();
    const auto index = d->ui.keyAlgoCB->findData(before);
    if (index != -1) {
        d->ui.keyAlgoCB->removeItem(index);
        d->ui.keyAlgoCB->insertItem(index, after, after);
        d->ui.keyAlgoCB->setCurrentIndex(currentIndex);
    }
}

void AddSubkeyDialog::loadDefaultKeyType()
{
    if (DeVSCompliance::isActive()) {
        for (const auto &algorithm : DeVSCompliance::preferredCompliantAlgorithms()) {
            if (d->ui.keyAlgoCB->findData(QString::fromStdString(algorithm)) != -1) {
                setKeyType(QString::fromStdString(algorithm));
                break;
            }
        }
        return;
    }
}

QDate AddSubkeyDialog::forceDateIntoAllowedRange(QDate date) const
{
    const auto minDate = d->ui.expiryDE->minimumDate();
    if (minDate.isValid() && date < minDate) {
        date = minDate;
    }
    const auto maxDate = d->ui.expiryDE->maximumDate();
    if (maxDate.isValid() && date > maxDate) {
        date = maxDate;
    }
    return date;
}

void AddSubkeyDialog::setExpiryDate(QDate date)
{
    if (date.isValid()) {
        d->ui.expiryDE->setDate(forceDateIntoAllowedRange(date));
    } else {
        if (unlimitedValidityIsAllowed()) {
            d->ui.expiryDE->setDate(date);
        }
    }
    if (d->ui.expiryCB->isEnabled()) {
        d->ui.expiryCB->setChecked(d->ui.expiryDE->isValid());
    }
}

KeyUsage AddSubkeyDialog::usage() const
{
    if (d->ui.signingCB->isChecked()) {
        return KeyUsage(KeyUsage::Sign);
    }
    if (d->ui.encryptionCB->isChecked()) {
        return KeyUsage(KeyUsage::Encrypt);
    }
    return KeyUsage(KeyUsage::Authenticate);
}
QString AddSubkeyDialog::algo() const
{
    return d->ui.keyAlgoCB->currentData().toString();
}

QDate AddSubkeyDialog::expires() const
{
    return d->ui.expiryCB->isChecked() ? d->ui.expiryDE->date() : QDate();
}

void AddSubkeyDialog::loadAlgorithms()
{
    if (!DeVSCompliance::isActive()) {
        d->ui.keyAlgoCB->addItem(i18nc("Default Algorithm", "Default"), QLatin1StringView("default"));
    }
    for (const auto &algorithm : DeVSCompliance::isActive() ? DeVSCompliance::compliantAlgorithms() : availableAlgorithms()) {
        d->ui.keyAlgoCB->addItem(Formatting::prettyAlgorithmName(algorithm), QString::fromStdString(algorithm));
    }
    d->ui.keyAlgoCB->setCurrentIndex(0);
}

#include "moc_addsubkeydialog.cpp"
