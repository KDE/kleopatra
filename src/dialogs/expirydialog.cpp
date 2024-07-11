/* -*- mode: c++; c-basic-offset:4 -*-
    dialogs/expirydialog.cpp

    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2008 Klarälvdalens Datakonsult AB
    SPDX-FileCopyrightText: 2021 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include <config-kleopatra.h>

#include "expirydialog.h"

#include "utils/accessibility.h"
#include "utils/expiration.h"
#include "utils/gui-helper.h"
#include "utils/qt-cxx20-compat.h"

#include <Libkleo/Formatting>

#include <KDateComboBox>
#include <KLocalizedString>
#include <KMessageBox>
#include <KStandardGuiItem>

#include <QCheckBox>
#include <QDate>
#include <QDialogButtonBox>
#include <QHBoxLayout>
#include <QLabel>
#include <QPushButton>
#include <QRadioButton>
#include <QVBoxLayout>

using namespace Kleo;
using namespace Kleo::Dialogs;

class ExpiryDialog::Private
{
    friend class ::Kleo::Dialogs::ExpiryDialog;
    ExpiryDialog *const q;

public:
    Private(Mode mode, ExpiryDialog *qq)
        : q{qq}
        , ui{mode, qq}
    {
        ui.neverRB->setEnabled(unlimitedValidityAllowed());
        ui.onRB->setEnabled(!fixedExpirationDate());

        connect(ui.onCB, &KDateComboBox::dateChanged, q, [this]() {
            slotOnDateChanged();
        });
    }

private:
    void slotOnDateChanged();

private:
    bool unlimitedValidityAllowed() const;
    bool fixedExpirationDate() const;
    void setInitialFocus();

private:
    bool initialFocusWasSet = false;

    struct UI {
        QRadioButton *neverRB;
        QRadioButton *onRB;
        KDateComboBox *onCB;
        QCheckBox *updateSubkeysCheckBox;
        QLabel *primaryKeyExpirationDate;
        LabelHelper labelHelper;

        explicit UI(Mode mode, Dialogs::ExpiryDialog *qq)
        {
            auto mainLayout = new QVBoxLayout{qq};

            auto mainWidget = new QWidget{qq};

            auto vboxLayout = new QVBoxLayout{mainWidget};
            vboxLayout->setContentsMargins(0, 0, 0, 0);

            {
                auto label = new QLabel{qq};
                label->setText(mode == Mode::UpdateIndividualSubkey ? i18n("Please select until when the subkey should be valid:")
                                                                    : i18n("Please select until when the certificate should be valid:"));
                vboxLayout->addWidget(label);
            }

            neverRB = new QRadioButton(i18n("Unlimited validity"), mainWidget);
            neverRB->setChecked(false);

            vboxLayout->addWidget(neverRB);

            {
                auto hboxLayout = new QHBoxLayout;

                onRB = new QRadioButton{i18n("Valid until:"), mainWidget};
                onRB->setChecked(true);

                hboxLayout->addWidget(onRB);

                onCB = new KDateComboBox{mainWidget};
                setUpExpirationDateComboBox(onCB);

                hboxLayout->addWidget(onCB);

                hboxLayout->addStretch(1);

                vboxLayout->addLayout(hboxLayout);
            }

            primaryKeyExpirationDate = new QLabel(qq);
            primaryKeyExpirationDate->setVisible(false);
            vboxLayout->addWidget(primaryKeyExpirationDate);
            labelHelper.addLabel(primaryKeyExpirationDate);

            {
                updateSubkeysCheckBox = new QCheckBox{i18n("Also update the validity period of the subkeys"), qq};
                updateSubkeysCheckBox->setVisible(mode == Mode::UpdateCertificateWithSubkeys);
                vboxLayout->addWidget(updateSubkeysCheckBox);
            }

            vboxLayout->addStretch(1);

            mainLayout->addWidget(mainWidget);

            auto buttonBox = new QDialogButtonBox{QDialogButtonBox::Ok | QDialogButtonBox::Cancel, qq};
            auto okButton = buttonBox->button(QDialogButtonBox::Ok);
            KGuiItem::assign(okButton, KStandardGuiItem::ok());
            okButton->setDefault(true);
            okButton->setShortcut(static_cast<int>(Qt::CTRL) | static_cast<int>(Qt::Key_Return));
            KGuiItem::assign(buttonBox->button(QDialogButtonBox::Cancel), KStandardGuiItem::cancel());
            qq->connect(buttonBox, &QDialogButtonBox::accepted, qq, &ExpiryDialog::accept);
            qq->connect(buttonBox, &QDialogButtonBox::rejected, qq, &QDialog::reject);

            mainLayout->addWidget(buttonBox);

            connect(onRB, &QRadioButton::toggled, onCB, &QWidget::setEnabled);
        }
    } ui;
};

void ExpiryDialog::Private::slotOnDateChanged()
{
    ui.onRB->setAccessibleName(i18nc("Valid until DATE", "Valid until %1", Formatting::accessibleDate(ui.onCB->date())));
}

bool Kleo::Dialogs::ExpiryDialog::Private::unlimitedValidityAllowed() const
{
    return !Kleo::maximumExpirationDate().isValid();
}

bool Kleo::Dialogs::ExpiryDialog::Private::fixedExpirationDate() const
{
    return ui.onCB->minimumDate() == ui.onCB->maximumDate();
}

void ExpiryDialog::Private::setInitialFocus()
{
    if (initialFocusWasSet) {
        return;
    }
    // give focus to the checked radio button
    (void)focusFirstCheckedButton({ui.neverRB, ui.onRB});
    initialFocusWasSet = true;
}

ExpiryDialog::ExpiryDialog(Mode mode, QWidget *p)
    : QDialog{p}
    , d{new Private{mode, this}}
{
    setWindowTitle(i18nc("@title:window", "Change Validity Period"));
}

ExpiryDialog::~ExpiryDialog() = default;

void ExpiryDialog::setDateOfExpiry(const QDate &date)
{
    const QDate current = QDate::currentDate();
    if (date.isValid()) {
        d->ui.onRB->setChecked(true);
        if (date <= current) {
            d->ui.onCB->setDate(defaultExpirationDate(ExpirationOnUnlimitedValidity::InternalDefaultExpiration));
        } else {
            d->ui.onCB->setDate(date);
        }
    } else {
        if (d->unlimitedValidityAllowed()) {
            d->ui.neverRB->setChecked(true);
        } else {
            d->ui.onRB->setChecked(true);
        }
        d->ui.onCB->setDate(defaultExpirationDate(ExpirationOnUnlimitedValidity::InternalDefaultExpiration));
    }
}

QDate ExpiryDialog::dateOfExpiry() const
{
    return d->ui.onRB->isChecked() ? d->ui.onCB->date() : QDate{};
}

void ExpiryDialog::setUpdateExpirationOfAllSubkeys(bool update)
{
    d->ui.updateSubkeysCheckBox->setChecked(update);
}

bool ExpiryDialog::updateExpirationOfAllSubkeys() const
{
    return d->ui.updateSubkeysCheckBox->isChecked();
}

void ExpiryDialog::accept()
{
    const auto date = dateOfExpiry();
    if (!Kleo::isValidExpirationDate(date)) {
        KMessageBox::error(this, i18nc("@info", "Error: %1", Kleo::validityPeriodHint()));
        return;
    }

    QDialog::accept();
}

void ExpiryDialog::showEvent(QShowEvent *event)
{
    d->setInitialFocus();
    QDialog::showEvent(event);
}

void ExpiryDialog::setPrimaryKey(const GpgME::Key &key)
{
    if (!key.subkey(0).neverExpires()) {
        d->ui.primaryKeyExpirationDate->setText(i18n("Expiration of primary key: %1", Kleo::Formatting::expirationDateString(key)));
        d->ui.onCB->setMaximumDate(Kleo::Formatting::expirationDate(key));
        d->ui.primaryKeyExpirationDate->setVisible(true);
        const auto keyExpiryDate = QDateTime::fromSecsSinceEpoch(quint32(key.subkey(0).expirationTime())).date();
        if (dateOfExpiry() > keyExpiryDate) {
            setDateOfExpiry(keyExpiryDate);
        }
    }
}

#include "moc_expirydialog.cpp"
