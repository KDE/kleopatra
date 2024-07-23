/*  view/pivcardwiget.cpp

    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2020 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include "pivcardwidget.h"

#include "tooltippreferences.h"

#include "commands/certificatetopivcardcommand.h"
#include "commands/changepincommand.h"
#include "commands/createcsrforcardkeycommand.h"
#include "commands/createopenpgpkeyfromcardkeyscommand.h"
#include "commands/importcertificatefrompivcardcommand.h"
#include "commands/keytocardcommand.h"
#include "commands/pivgeneratecardkeycommand.h"
#include "commands/setpivcardapplicationadministrationkeycommand.h"

#include "smartcard/pivcard.h"
#include "smartcard/readerstatus.h"

#include <Libkleo/Compliance>
#include <Libkleo/Dn>
#include <Libkleo/Formatting>
#include <Libkleo/KeyCache>

#include <KLocalizedString>
#include <KSeparator>

#include <QGridLayout>
#include <QLabel>
#include <QPushButton>
#include <QVBoxLayout>

using namespace GpgME;
using namespace Kleo;
using namespace Kleo::Commands;
using namespace Kleo::SmartCard;

namespace
{
static void layoutKeyWidgets(QGridLayout *grid, const QString &keyName, const PIVCardWidget::KeyWidgets &keyWidgets)
{
    int row = grid->rowCount();
    grid->addWidget(new QLabel(keyName), row, 0);
    grid->addWidget(keyWidgets.keyGrip, row, 1);
    grid->addWidget(keyWidgets.keyAlgorithm, row, 2);
    grid->addWidget(keyWidgets.generateButton, row, 3);
    if (keyWidgets.writeKeyButton) {
        grid->addWidget(keyWidgets.writeKeyButton, row, 4);
    }

    row++;
    grid->addWidget(keyWidgets.certificateInfo, row, 1, 1, 2);
    grid->addWidget(keyWidgets.writeCertificateButton, row, 3);
    grid->addWidget(keyWidgets.importCertificateButton, row, 4);
    if (keyWidgets.createCSRButton) {
        grid->addWidget(keyWidgets.createCSRButton, row, 5);
    }
}

static int toolTipOptions()
{
    using namespace Kleo::Formatting;
    static const int validityFlags = Validity | Issuer | ExpiryDates | CertificateUsage;
    static const int ownerFlags = Subject | UserIDs | OwnerTrust;
    static const int detailsFlags = StorageLocation | CertificateType | SerialNumber | Fingerprint;

    const TooltipPreferences prefs;

    int flags = KeyID;
    flags |= prefs.showValidity() ? validityFlags : 0;
    flags |= prefs.showOwnerInformation() ? ownerFlags : 0;
    flags |= prefs.showCertificateDetails() ? detailsFlags : 0;
    return flags;
}
}

PIVCardWidget::PIVCardWidget(QWidget *parent)
    : SmartCardWidget(parent)
{
    mContentLayout->addWidget(new KSeparator(Qt::Horizontal));

    mContentLayout->addWidget(new QLabel(QStringLiteral("<b>%1</b>").arg(i18n("Keys:")), this));

    auto keysGrid = new QGridLayout;
    for (const auto &keyInfo : PIVCard::supportedKeys()) {
        KeyWidgets keyWidgets = createKeyWidgets(keyInfo);
        layoutKeyWidgets(keysGrid, PIVCard::keyDisplayName(keyInfo.keyRef), keyWidgets);
    }
    mContentLayout->addLayout(keysGrid);

    mContentLayout->addWidget(new KSeparator(Qt::Horizontal));

    auto actionLayout = new QHBoxLayout;

    if (CreateOpenPGPKeyFromCardKeysCommand::isSupported()) {
        mKeyForCardKeysButton = new QPushButton(this);
        mKeyForCardKeysButton->setText(i18nc("@action:button", "Create OpenPGP Key"));
        mKeyForCardKeysButton->setToolTip(i18nc("@info:tooltip", "Create an OpenPGP key for the keys stored on the card."));
        actionLayout->addWidget(mKeyForCardKeysButton);
        connect(mKeyForCardKeysButton, &QPushButton::clicked, this, &PIVCardWidget::createKeyFromCardKeys);
    }

    {
        auto button = new QPushButton(i18nc("@action:button", "Change PIN"), this);
        button->setToolTip(i18nc("@info:tooltip",
                                 "Change the PIV Card Application PIN that activates the PIV Card "
                                 "and enables private key operations using the stored keys."));
        actionLayout->addWidget(button);
        connect(button, &QPushButton::clicked, this, [this]() {
            changePin(PIVCard::pinKeyRef());
        });
    }
    {
        auto button = new QPushButton(i18nc("@action:button", "Change PUK"), this);
        button->setToolTip(i18nc("@info:tooltip", "Change the PIN Unblocking Key that enables a reset of the PIN."));
        actionLayout->addWidget(button);
        connect(button, &QPushButton::clicked, this, [this]() {
            changePin(PIVCard::pukKeyRef());
        });
    }
    {
        auto button = new QPushButton(i18nc("@action:button", "Change Admin Key"), this);
        button->setToolTip(i18nc("@info:tooltip",
                                 "Change the PIV Card Application Administration Key that is used by the "
                                 "PIV Card Application to authenticate the PIV Card Application Administrator and by the "
                                 "administrator (resp. Kleopatra) to authenticate the PIV Card Application."));
        actionLayout->addWidget(button);
        connect(button, &QPushButton::clicked, this, [this]() {
            setAdminKey();
        });
    }

    actionLayout->addStretch(-1);
    mContentLayout->addLayout(actionLayout);

    mContentLayout->addStretch(1);
}

PIVCardWidget::KeyWidgets PIVCardWidget::createKeyWidgets(const KeyPairInfo &keyInfo)
{
    const std::string keyRef = keyInfo.keyRef;
    KeyWidgets keyWidgets;
    keyWidgets.keyGrip = new QLabel(this);
    keyWidgets.keyGrip->setTextInteractionFlags(Qt::TextBrowserInteraction);
    keyWidgets.keyAlgorithm = new QLabel(this);
    keyWidgets.keyAlgorithm->setTextInteractionFlags(Qt::TextSelectableByMouse);
    keyWidgets.generateButton = new QPushButton(i18nc("@action:button", "Generate"), this);
    keyWidgets.generateButton->setEnabled(false);
    connect(keyWidgets.generateButton, &QPushButton::clicked, this, [this, keyRef]() {
        generateKey(keyRef);
    });
    if (keyRef == PIVCard::cardAuthenticationKeyRef() || keyRef == PIVCard::keyManagementKeyRef()) {
        keyWidgets.writeKeyButton = new QPushButton(i18nc("@action:button", "Write Key"), this);
        keyWidgets.writeKeyButton->setToolTip(i18nc("@info:tooltip", "Write the key pair of a certificate to the card"));
        keyWidgets.writeKeyButton->setEnabled(true);
        connect(keyWidgets.writeKeyButton, &QPushButton::clicked, this, [this, keyRef]() {
            writeKeyToCard(keyRef);
        });
    }
    keyWidgets.certificateInfo = new QLabel(this);
    keyWidgets.certificateInfo->setTextInteractionFlags(Qt::TextBrowserInteraction);
    keyWidgets.writeCertificateButton = new QPushButton(i18nc("@action:button", "Write Certificate"), this);
    keyWidgets.writeCertificateButton->setToolTip(i18nc("@info:tooltip", "Write the certificate corresponding to this key to the card"));
    keyWidgets.writeCertificateButton->setEnabled(false);
    connect(keyWidgets.writeCertificateButton, &QPushButton::clicked, this, [this, keyRef]() {
        writeCertificateToCard(keyRef);
    });
    keyWidgets.importCertificateButton = new QPushButton(i18nc("@action:button", "Import Certificate"), this);
    keyWidgets.importCertificateButton->setToolTip(i18nc("@info:tooltip", "Import the certificate stored on the card"));
    keyWidgets.importCertificateButton->setEnabled(false);
    connect(keyWidgets.importCertificateButton, &QPushButton::clicked, this, [this, keyRef]() {
        importCertificateFromCard(keyRef);
    });
    if (keyInfo.canSign() || keyInfo.canEncrypt()) {
        keyWidgets.createCSRButton = new QPushButton(i18nc("@action:button", "Create CSR"), this);
        keyWidgets.createCSRButton->setToolTip(i18nc("@info:tooltip", "Create a certificate signing request for this key"));
        keyWidgets.createCSRButton->setEnabled(false);
        connect(keyWidgets.createCSRButton, &QPushButton::clicked, this, [this, keyRef]() {
            createCSR(keyRef);
        });
    }
    mKeyWidgets.insert({keyRef, keyWidgets});
    return keyWidgets;
}

PIVCardWidget::~PIVCardWidget()
{
}

void PIVCardWidget::setCard(const PIVCard *card)
{
    SmartCardWidget::setCard(card);

    if (card) {
        updateCachedValues(PIVCard::pivAuthenticationKeyRef(), card);
        updateCachedValues(PIVCard::cardAuthenticationKeyRef(), card);
        updateCachedValues(PIVCard::digitalSignatureKeyRef(), card);
        updateCachedValues(PIVCard::keyManagementKeyRef(), card);
    }
    updateKeyWidgets(PIVCard::pivAuthenticationKeyRef());
    updateKeyWidgets(PIVCard::cardAuthenticationKeyRef());
    updateKeyWidgets(PIVCard::digitalSignatureKeyRef());
    updateKeyWidgets(PIVCard::keyManagementKeyRef());

    if (mKeyForCardKeysButton) {
        mKeyForCardKeysButton->setEnabled(card->hasSigningKey() //
                                          && card->hasEncryptionKey() //
                                          && DeVSCompliance::algorithmIsCompliant(card->keyInfo(card->signingKeyRef()).algorithm)
                                          && DeVSCompliance::algorithmIsCompliant(card->keyInfo(card->encryptionKeyRef()).algorithm));
    }
}

void PIVCardWidget::updateCachedValues(const std::string &keyRef, const SmartCard::PIVCard *card)
{
    KeyWidgets &widgets = mKeyWidgets.at(keyRef);
    widgets.keyInfo = card->keyInfo(keyRef);
    widgets.certificateData = card->certificateData(keyRef);
}

void PIVCardWidget::updateKeyWidgets(const std::string &keyRef)
{
    const KeyWidgets &widgets = mKeyWidgets.at(keyRef);
    const std::string grip = widgets.keyInfo.grip;
    if (grip.empty()) {
        widgets.certificateInfo->setText(i18nc("@info", "<em>slot empty</em>"));
        widgets.certificateInfo->setToolTip(QString());
        widgets.keyGrip->setText(QString());
        widgets.keyAlgorithm->setText(QString());
        widgets.generateButton->setText(i18nc("@action:button", "Generate"));
        widgets.generateButton->setToolTip(i18nc("@info:tooltip %1 display name of a key", "Generate %1", PIVCard::keyDisplayName(keyRef)));
        if (widgets.createCSRButton) {
            widgets.createCSRButton->setEnabled(false);
        }
        widgets.writeCertificateButton->setEnabled(false);
        widgets.importCertificateButton->setEnabled(false);
    } else {
        const Key certificate = KeyCache::instance()->findSubkeyByKeyGrip(grip, GpgME::CMS).parent();
        if (!certificate.isNull()) {
            widgets.certificateInfo->setText(i18nc("X.509 certificate DN (validity, created: date)",
                                                   "%1 (%2, created: %3)",
                                                   DN(certificate.userID(0).id()).prettyDN(),
                                                   Formatting::complianceStringShort(certificate),
                                                   Formatting::creationDateString(certificate)));
            widgets.certificateInfo->setToolTip(Formatting::toolTip(certificate, toolTipOptions()));
            widgets.writeCertificateButton->setEnabled(true);
        } else {
            widgets.certificateInfo->setText(i18nc("@info", "<em>no matching certificate</em>"));
            widgets.certificateInfo->setToolTip(QString());
            widgets.writeCertificateButton->setEnabled(false);
        }
        widgets.keyGrip->setText(QString::fromStdString(grip));
        const std::string algo = widgets.keyInfo.algorithm;
        widgets.keyAlgorithm->setText(algo.empty() ? i18nc("@info unknown key algorithm", "unknown") : QString::fromStdString(algo));
        widgets.importCertificateButton->setEnabled(!widgets.certificateData.empty());

        widgets.generateButton->setText(i18nc("@action:button", "Replace"));
        widgets.generateButton->setToolTip(i18nc("@info:tooltip %1 display name of a key", "Replace %1 with new key", PIVCard::keyDisplayName(keyRef)));
        if (widgets.createCSRButton) {
            widgets.createCSRButton->setEnabled(DeVSCompliance::algorithmIsCompliant(algo));
        }
    }

    widgets.generateButton->setEnabled(true);
}

void PIVCardWidget::generateKey(const std::string &keyref)
{
    auto cmd = new PIVGenerateCardKeyCommand(serialNumber(), this);
    this->setEnabled(false);
    connect(cmd, &PIVGenerateCardKeyCommand::finished, this, [this]() {
        this->setEnabled(true);
    });
    cmd->setKeyRef(keyref);
    cmd->start();
}

void PIVCardWidget::createCSR(const std::string &keyref)
{
    auto cmd = new CreateCSRForCardKeyCommand(keyref, serialNumber(), PIVCard::AppName, this);
    this->setEnabled(false);
    connect(cmd, &CreateCSRForCardKeyCommand::finished, this, [this]() {
        this->setEnabled(true);
    });
    cmd->start();
}

void PIVCardWidget::writeCertificateToCard(const std::string &keyref)
{
    auto cmd = new CertificateToPIVCardCommand(keyref, serialNumber());
    this->setEnabled(false);
    connect(cmd, &CertificateToPIVCardCommand::finished, this, [this]() {
        this->setEnabled(true);
    });
    cmd->setParentWidget(this);
    cmd->start();
}

void PIVCardWidget::importCertificateFromCard(const std::string &keyref)
{
    auto cmd = new ImportCertificateFromPIVCardCommand(keyref, serialNumber());
    this->setEnabled(false);
    connect(cmd, &ImportCertificateFromPIVCardCommand::finished, this, [this, keyref]() {
        this->updateKeyWidgets(keyref);
        this->setEnabled(true);
    });
    cmd->setParentWidget(this);
    cmd->start();
}

void PIVCardWidget::writeKeyToCard(const std::string &keyref)
{
    auto cmd = new KeyToCardCommand(keyref, serialNumber(), PIVCard::AppName);
    this->setEnabled(false);
    connect(cmd, &KeyToCardCommand::finished, this, [this]() {
        this->setEnabled(true);
    });
    cmd->setParentWidget(this);
    cmd->start();
}

void PIVCardWidget::createKeyFromCardKeys()
{
    auto cmd = new CreateOpenPGPKeyFromCardKeysCommand(serialNumber(), PIVCard::AppName, this);
    this->setEnabled(false);
    connect(cmd, &CreateOpenPGPKeyFromCardKeysCommand::finished, this, [this]() {
        this->setEnabled(true);
    });
    cmd->start();
}

void PIVCardWidget::changePin(const std::string &keyRef)
{
    auto cmd = new ChangePinCommand(serialNumber(), PIVCard::AppName, this);
    this->setEnabled(false);
    connect(cmd, &ChangePinCommand::finished, this, [this]() {
        this->setEnabled(true);
    });
    cmd->setKeyRef(keyRef);
    cmd->start();
}

void PIVCardWidget::setAdminKey()
{
    auto cmd = new SetPIVCardApplicationAdministrationKeyCommand(serialNumber(), this);
    this->setEnabled(false);
    connect(cmd, &SetPIVCardApplicationAdministrationKeyCommand::finished, this, [this]() {
        this->setEnabled(true);
    });
    cmd->start();
}
