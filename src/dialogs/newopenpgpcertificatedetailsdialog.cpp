/* -*- mode: c++; c-basic-offset:4 -*-
    dialogs/newopenpgpcertificatedetailsdialog.cpp

    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2008 Klarälvdalens Datakonsult AB
    SPDX-FileCopyrightText: 2022 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include <config-kleopatra.h>

#include "newopenpgpcertificatedetailsdialog.h"

#include "nameandemailwidget.h"

#include "dialogs/animatedexpander.h"
#include "newcertificatewizard/keyalgo_p.h"
#include "utils/expiration.h"
#include "utils/keyparameters.h"
#include "utils/scrollarea.h"

#include <settings.h>

#include <Libkleo/Compat>
#include <Libkleo/Compliance>
#include <Libkleo/Formatting>
#include <Libkleo/GnuPG>
#include <Libkleo/KeyUsage>

#include <KConfigGroup>
#include <KDateComboBox>
#include <KLocalizedString>
#include <KMessageBox>
#include <KSeparator>
#include <KSharedConfig>

#include <QCheckBox>
#include <QDialogButtonBox>
#include <QLabel>
#include <QPushButton>
#include <QVBoxLayout>

#include <QGpgME/CryptoConfig>
#include <QGpgME/Protocol>

#include "kleopatra_debug.h"

using namespace Kleo;
using namespace Kleo::NewCertificateUi;

static bool unlimitedValidityIsAllowed()
{
    return !Kleo::maximumExpirationDate().isValid();
}

class NewOpenPGPCertificateDetailsDialog::Private
{
    friend class ::Kleo::NewOpenPGPCertificateDetailsDialog;
    NewOpenPGPCertificateDetailsDialog *const q;

    struct UI {
        QLabel *infoLabel;
        ScrollArea *scrollArea;
        NameAndEmailWidget *nameAndEmail;
        QCheckBox *withPassCheckBox;
        QDialogButtonBox *buttonBox;
        QCheckBox *expiryCB;
        KDateComboBox *expiryDE;
        QComboBox *keyAlgoCB;
        QLabel *keyAlgoLabel;
        AnimatedExpander *expander;

        UI(QWidget *dialog)
        {
            auto mainLayout = new QVBoxLayout{dialog};

            infoLabel = new QLabel{dialog};
            infoLabel->setWordWrap(true);
            mainLayout->addWidget(infoLabel);

            mainLayout->addWidget(new KSeparator{Qt::Horizontal, dialog});

            scrollArea = new ScrollArea{dialog};
            scrollArea->setFocusPolicy(Qt::NoFocus);
            scrollArea->setFrameStyle(QFrame::NoFrame);
            scrollArea->setBackgroundRole(dialog->backgroundRole());
            scrollArea->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
            scrollArea->setSizeAdjustPolicy(QScrollArea::AdjustToContents);
            auto scrollAreaLayout = qobject_cast<QBoxLayout *>(scrollArea->widget()->layout());
            scrollAreaLayout->setContentsMargins(0, 0, 0, 0);

            nameAndEmail = new NameAndEmailWidget{dialog};
            nameAndEmail->layout()->setContentsMargins(0, 0, 0, 0);
            scrollAreaLayout->addWidget(nameAndEmail);

            withPassCheckBox = new QCheckBox{i18n("Protect the generated key with a passphrase."), dialog};
            withPassCheckBox->setToolTip(
                i18n("Encrypts the secret key with an unrecoverable passphrase. You will be asked for the passphrase during key generation."));
            scrollAreaLayout->addWidget(withPassCheckBox);

            expander = new AnimatedExpander(i18n("Advanced options"), {}, dialog);
            scrollAreaLayout->addWidget(expander);

            auto advancedLayout = new QVBoxLayout;
            expander->setContentLayout(advancedLayout);

            keyAlgoLabel = new QLabel(dialog);
            keyAlgoLabel->setText(i18nc("The algorithm and strength of encryption key", "Key Material"));
            auto font = keyAlgoLabel->font();
            font.setBold(true);
            keyAlgoLabel->setFont(font);
            advancedLayout->addWidget(keyAlgoLabel);

            keyAlgoCB = new QComboBox(dialog);
            keyAlgoLabel->setBuddy(keyAlgoCB);
            advancedLayout->addWidget(keyAlgoCB);

            {
                auto hbox = new QHBoxLayout;

                expiryCB = new QCheckBox{Kleo::validUntilLabel(), dialog};
                hbox->addWidget(expiryCB);

                expiryDE = new KDateComboBox(dialog);
                hbox->addWidget(expiryDE, 1);

                advancedLayout->addLayout(hbox);
            }

            scrollAreaLayout->addStretch(1);

            mainLayout->addWidget(scrollArea);

            mainLayout->addWidget(new KSeparator{Qt::Horizontal, dialog});

            buttonBox = new QDialogButtonBox{QDialogButtonBox::Ok | QDialogButtonBox::Cancel, dialog};

            mainLayout->addWidget(buttonBox);
        }
    } ui;

public:
    explicit Private(NewOpenPGPCertificateDetailsDialog *qq)
        : q{qq}
        , ui{qq}
        , technicalParameters{KeyParameters::OpenPGP}
    {
        q->setWindowTitle(i18nc("title:window", "Create OpenPGP Certificate"));

        const KConfigGroup config{KSharedConfig::openConfig(), "CertificateCreationWizard"};
        const auto attrOrder = config.readEntry("OpenPGPAttributeOrder", QStringList{});
        const auto nameIsRequired = attrOrder.contains(QLatin1String{"NAME!"}, Qt::CaseInsensitive);
        const auto emailIsRequired = attrOrder.contains(QLatin1String{"EMAIL!"}, Qt::CaseInsensitive);

        ui.infoLabel->setText(nameIsRequired || emailIsRequired //
                                  ? i18n("Enter a name and an email address to use for the certificate.")
                                  : i18n("Enter a name and/or an email address to use for the certificate."));

        ui.nameAndEmail->setNameIsRequired(nameIsRequired);
        ui.nameAndEmail->setNameLabel(config.readEntry("NAME_label"));
        ui.nameAndEmail->setNameHint(config.readEntry("NAME_hint", config.readEntry("NAME_placeholder")));
        ui.nameAndEmail->setNamePattern(config.readEntry("NAME_regex"));
        ui.nameAndEmail->setEmailIsRequired(emailIsRequired);
        ui.nameAndEmail->setEmailLabel(config.readEntry("EMAIL_label"));
        ui.nameAndEmail->setEmailHint(config.readEntry("EMAIL_hint", config.readEntry("EMAIL_placeholder")));
        ui.nameAndEmail->setEmailPattern(config.readEntry("EMAIL_regex"));

        Settings settings;
        ui.expander->setVisible(!settings.hideAdvanced());

        const auto conf = QGpgME::cryptoConfig();
        const auto entry = getCryptoConfigEntry(conf, "gpg-agent", "enforce-passphrase-constraints");
        if (entry && entry->boolValue()) {
            qCDebug(KLEOPATRA_LOG) << "Disabling passphrase check box because of agent config.";
            ui.withPassCheckBox->setEnabled(false);
            ui.withPassCheckBox->setChecked(true);
        } else {
            ui.withPassCheckBox->setChecked(config.readEntry("WithPassphrase", false));
            ui.withPassCheckBox->setEnabled(!config.isEntryImmutable("WithPassphrase"));
        }

        connect(ui.buttonBox, &QDialogButtonBox::accepted, q, [this]() {
            checkAccept();
        });
        connect(ui.buttonBox, &QDialogButtonBox::rejected, q, &QDialog::reject);

        for (const auto &algorithm : DeVSCompliance::isActive() ? DeVSCompliance::compliantAlgorithms() : availableAlgorithms()) {
            ui.keyAlgoCB->addItem(QString::fromStdString(algorithm), QString::fromStdString(algorithm));
        }
        auto cryptoConfig = QGpgME::cryptoConfig();
        if (cryptoConfig) {
            auto pubkeyEntry = getCryptoConfigEntry(QGpgME::cryptoConfig(), "gpg", "default_pubkey_algo");
            if (pubkeyEntry) {
                auto algo = pubkeyEntry->stringValue().split(QLatin1Char('/'))[0];
                if (algo == QStringLiteral("ed25519")) {
                    algo = QStringLiteral("curve25519");
                } else if (algo == QStringLiteral("ed448")) {
                    algo = QStringLiteral("curve448");
                }
                auto index = ui.keyAlgoCB->findData(algo);
                if (index != -1) {
                    ui.keyAlgoCB->setCurrentIndex(index);
                } else {
                    ui.keyAlgoCB->setCurrentIndex(0);
                }
            } else {
                ui.keyAlgoCB->setCurrentIndex(0);
            }
        } else {
            ui.keyAlgoCB->setCurrentIndex(0);
        }

        Kleo::setUpExpirationDateComboBox(ui.expiryDE);
        ui.expiryCB->setEnabled(true);
        setExpiryDate(defaultExpirationDate(ExpirationOnUnlimitedValidity::InternalDefaultExpiration));
        if (unlimitedValidityIsAllowed()) {
            ui.expiryDE->setEnabled(ui.expiryCB->isChecked());
        } else {
            ui.expiryCB->setEnabled(false);
        }
        connect(ui.expiryCB, &QAbstractButton::toggled, q, [this](bool checked) {
            ui.expiryDE->setEnabled(checked);
            if (checked && !ui.expiryDE->isValid()) {
                setExpiryDate(defaultExpirationDate(ExpirationOnUnlimitedValidity::InternalDefaultExpiration));
            }
            updateTechnicalParameters();
        });
        connect(ui.expiryDE, &KDateComboBox::dateChanged, q, [this]() {
            updateTechnicalParameters();
        });
        connect(ui.keyAlgoCB, &QComboBox::currentIndexChanged, q, [this]() {
            updateTechnicalParameters();
        });
        updateTechnicalParameters(); // set key parameters to default values for OpenPGP
        connect(ui.expander, &AnimatedExpander::startExpanding, q, [this]() {
            q->resize(std::max(q->sizeHint().width(), ui.expander->contentWidth()) + 20, q->sizeHint().height() + ui.expander->contentHeight() + 20);
        });
    }

private:
    void updateTechnicalParameters()
    {
        technicalParameters = KeyParameters{KeyParameters::OpenPGP};
        auto keyType = GpgME::Subkey::AlgoUnknown;
        auto subkeyType = GpgME::Subkey::AlgoUnknown;
        auto algoString = ui.keyAlgoCB->currentData().toString();
        if (algoString.startsWith(QStringLiteral("rsa"))) {
            keyType = GpgME::Subkey::AlgoRSA;
            subkeyType = GpgME::Subkey::AlgoRSA;
            const auto strength = algoString.mid(3).toInt();
            technicalParameters.setKeyLength(strength);
            technicalParameters.setSubkeyLength(strength);
        } else if (algoString == QStringLiteral("curve25519") || algoString == QStringLiteral("curve448")) {
            keyType = GpgME::Subkey::AlgoEDDSA;
            subkeyType = GpgME::Subkey::AlgoECDH;
            if (algoString.endsWith(QStringLiteral("25519"))) {
                technicalParameters.setKeyCurve(QStringLiteral("ed25519"));
                technicalParameters.setSubkeyCurve(QStringLiteral("cv25519"));
            } else {
                technicalParameters.setKeyCurve(QStringLiteral("ed448"));
                technicalParameters.setSubkeyCurve(QStringLiteral("cv448"));
            }
        } else {
            keyType = GpgME::Subkey::AlgoECDSA;
            subkeyType = GpgME::Subkey::AlgoECDH;
            technicalParameters.setKeyCurve(algoString);
            technicalParameters.setSubkeyCurve(algoString);
        }
        technicalParameters.setKeyType(keyType);
        technicalParameters.setSubkeyType(subkeyType);

        technicalParameters.setKeyUsage(KeyUsage(KeyUsage::Certify | KeyUsage::Sign));
        technicalParameters.setSubkeyUsage(KeyUsage(KeyUsage::Encrypt));

        technicalParameters.setExpirationDate(expiryDate());
        // name and email are set later
    }

    QDate expiryDate() const
    {
        return ui.expiryCB->isChecked() ? ui.expiryDE->date() : QDate{};
    }

    void setTechnicalParameters(const KeyParameters &parameters)
    {
        int index;
        if (parameters.keyType() == GpgME::Subkey::AlgoRSA_S) {
            index = ui.keyAlgoCB->findData(QStringLiteral("rsa%1").arg(parameters.keyLength()));
        } else {
            index = ui.keyAlgoCB->findData(parameters.keyCurve());
        }
        ui.keyAlgoCB->setCurrentIndex(index);
        setExpiryDate(parameters.expirationDate());
    }

    void checkAccept()
    {
        QStringList errors;
        if (ui.nameAndEmail->userID().isEmpty() && !ui.nameAndEmail->nameIsRequired() && !ui.nameAndEmail->emailIsRequired()) {
            errors.push_back(i18n("Enter a name or an email address."));
        }
        const auto nameError = ui.nameAndEmail->nameError();
        if (!nameError.isEmpty()) {
            errors.push_back(nameError);
        }
        const auto emailError = ui.nameAndEmail->emailError();
        if (!emailError.isEmpty()) {
            errors.push_back(emailError);
        }
        if (!Kleo::isValidExpirationDate(expiryDate())) {
            errors.push_back(Kleo::validityPeriodHint());
        }
        if (errors.size() > 1) {
            KMessageBox::errorList(q, i18n("There is a problem."), errors);
        } else if (!errors.empty()) {
            KMessageBox::error(q, errors.first());
        } else {
            q->accept();
        }
    }

    QDate forceDateIntoAllowedRange(QDate date) const
    {
        const auto minDate = ui.expiryDE->minimumDate();
        if (minDate.isValid() && date < minDate) {
            date = minDate;
        }
        const auto maxDate = ui.expiryDE->maximumDate();
        if (maxDate.isValid() && date > maxDate) {
            date = maxDate;
        }
        return date;
    }

    void setExpiryDate(QDate date)
    {
        if (date.isValid()) {
            ui.expiryDE->setDate(forceDateIntoAllowedRange(date));
        } else {
            // check if unlimited validity is allowed
            if (unlimitedValidityIsAllowed()) {
                ui.expiryDE->setDate(date);
            }
        }
        if (ui.expiryCB->isEnabled()) {
            ui.expiryCB->setChecked(ui.expiryDE->isValid());
        }
    }

private:
    KeyParameters technicalParameters;
};

NewOpenPGPCertificateDetailsDialog::NewOpenPGPCertificateDetailsDialog(QWidget *parent, Qt::WindowFlags f)
    : QDialog{parent, f}
    , d(new Private{this})
{
    resize(std::max(sizeHint().width(), d->ui.expander->contentWidth()) + 20, sizeHint().height() + 20);
}

NewOpenPGPCertificateDetailsDialog::~NewOpenPGPCertificateDetailsDialog() = default;

void NewOpenPGPCertificateDetailsDialog::setName(const QString &name)
{
    d->ui.nameAndEmail->setName(name);
}

QString NewOpenPGPCertificateDetailsDialog::name() const
{
    return d->ui.nameAndEmail->name();
}

void NewOpenPGPCertificateDetailsDialog::setEmail(const QString &email)
{
    d->ui.nameAndEmail->setEmail(email);
}

QString NewOpenPGPCertificateDetailsDialog::email() const
{
    return d->ui.nameAndEmail->email();
}

void Kleo::NewOpenPGPCertificateDetailsDialog::setKeyParameters(const Kleo::KeyParameters &parameters)
{
    setName(parameters.name());
    const auto emails = parameters.emails();
    if (!emails.empty()) {
        setEmail(emails.front());
    }
    d->setTechnicalParameters(parameters);
}

KeyParameters NewOpenPGPCertificateDetailsDialog::keyParameters() const
{
    // set name and email on a copy of the technical parameters
    auto parameters = d->technicalParameters;
    if (!name().isEmpty()) {
        parameters.setName(name());
    }
    if (!email().isEmpty()) {
        parameters.setEmail(email());
    }
    return parameters;
}

void Kleo::NewOpenPGPCertificateDetailsDialog::setProtectKeyWithPassword(bool protectKey)
{
    d->ui.withPassCheckBox->setChecked(protectKey);
}

bool NewOpenPGPCertificateDetailsDialog::protectKeyWithPassword() const
{
    return d->ui.withPassCheckBox->isChecked();
}
