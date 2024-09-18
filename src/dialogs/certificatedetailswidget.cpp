/*
    dialogs/certificatedetailswidget.cpp

    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2016 Klarälvdalens Datakonsult AB
    SPDX-FileCopyrightText: 2017 Intevation GmbH
    SPDX-FileCopyrightText: 2022 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>
    SPDX-FileCopyrightText: 2022 Felix Tiede

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include <config-kleopatra.h>

#include "certificatedetailswidget.h"

#include "cardinfotab.h"
#include "certificatedumpwidget.h"
#include "dialogs/weboftrustwidget.h"
#include "kleopatra_debug.h"
#include "revokerswidget.h"
#include "subkeyswidget.h"
#include "trustchainwidget.h"
#include "useridswidget.h"

#include "commands/changeexpirycommand.h"
#include "commands/detailscommand.h"
#include "utils/accessibility.h"
#include "utils/tags.h"
#include "view/infofield.h"

#include <Libkleo/Algorithm>
#include <Libkleo/Compliance>
#include <Libkleo/Dn>
#include <Libkleo/Formatting>
#include <Libkleo/GnuPG>
#include <Libkleo/KeyCache>
#include <Libkleo/KeyHelpers>
#include <Libkleo/TreeWidget>

#include <KLocalizedString>
#include <KMessageBox>
#include <KSeparator>

#include <gpgme++/context.h>
#include <gpgme++/key.h>
#include <gpgme++/keylistresult.h>

#include <gpgme.h>

#include <QGpgME/Debug>
#include <QGpgME/KeyListJob>
#include <QGpgME/Protocol>

#include <QClipboard>
#include <QDateTime>
#include <QGridLayout>
#include <QGuiApplication>
#include <QHBoxLayout>
#include <QLabel>
#include <QListWidget>
#include <QLocale>
#include <QMenu>
#include <QPushButton>
#include <QStackedWidget>
#include <QStringBuilder>
#include <QTreeWidget>
#include <QVBoxLayout>

#include <map>
#if __has_include(<ranges>)
#include <ranges>
#if defined(__cpp_lib_ranges) && __cpp_lib_ranges >= 201911L
#define USE_RANGES
#endif
#endif
#include <set>

Q_DECLARE_METATYPE(GpgME::UserID)

using namespace Kleo;

class CertificateDetailsWidget::Private
{
public:
    Private(CertificateDetailsWidget *qq);

    void setupCommonProperties();
    void setUpSMIMEAdressList();
    void setupPGPProperties();
    void setupSMIMEProperties();

    void refreshCertificate();
    void changeExpiration();
    void keysMayHaveChanged();

    QIcon trustLevelIcon(const GpgME::UserID &uid) const;
    QString trustLevelText(const GpgME::UserID &uid) const;

    void showIssuerCertificate();

    void updateKey();
    void setUpdatedKey(const GpgME::Key &key);
    void keyListDone(const GpgME::KeyListResult &, const std::vector<GpgME::Key> &, const QString &, const GpgME::Error &);
    void copyFingerprintToClipboard();
    void setUpdateInProgress(bool updateInProgress);
    void setTabVisible(QWidget *tab, bool visible);

private:
    CertificateDetailsWidget *const q;

public:
    GpgME::Key key;
    bool updateInProgress = false;

private:
    InfoField *attributeField(const QString &attributeName)
    {
        const auto keyValuePairIt = ui.smimeAttributeFields.find(attributeName);
        if (keyValuePairIt != ui.smimeAttributeFields.end()) {
            return (*keyValuePairIt).second.get();
        }
        return nullptr;
    }

private:
    struct UI {
        UserIdsWidget *userIDs = nullptr;

        std::map<QString, std::unique_ptr<InfoField>> smimeAttributeFields;
        std::unique_ptr<InfoField> smimeTrustLevelField;
        std::unique_ptr<InfoField> validFromField;
        std::unique_ptr<InfoField> expiresField;
        QAction *changeExpirationAction = nullptr;
        std::unique_ptr<InfoField> fingerprintField;
        QAction *copyFingerprintAction = nullptr;
        std::unique_ptr<InfoField> smimeIssuerField;
        QAction *showIssuerCertificateAction = nullptr;
        std::unique_ptr<InfoField> complianceField;
        std::unique_ptr<InfoField> trustedIntroducerField;
        std::unique_ptr<InfoField> primaryUserIdField;
        std::unique_ptr<InfoField> privateKeyInfoField;
        std::unique_ptr<InfoField> statusField;
        std::unique_ptr<InfoField> usageField;

        QListWidget *smimeAddressList = nullptr;

        QTabWidget *tabWidget = nullptr;
        SubKeysWidget *subKeysWidget = nullptr;
        WebOfTrustWidget *webOfTrustWidget = nullptr;
        TrustChainWidget *trustChainWidget = nullptr;
        CertificateDumpWidget *certificateDumpWidget = nullptr;
        CardInfoTab *cardInfoTab = nullptr;
        RevokersWidget *revokersWidget = nullptr;

        void setupUi(QWidget *parent)
        {
            auto mainLayout = new QVBoxLayout{parent};

            {
                auto gridLayout = new QGridLayout;
                gridLayout->setColumnStretch(1, 1);

                int row = -1;

                row++;
                primaryUserIdField = std::make_unique<InfoField>(i18n("User ID:"), parent);
                gridLayout->addWidget(primaryUserIdField->label(), row, 0);
                gridLayout->addLayout(primaryUserIdField->layout(), row, 1);

                for (const auto &attribute : DN::attributeOrder()) {
                    const auto attributeLabel = DN::attributeNameToLabel(attribute);
                    if (attributeLabel.isEmpty()) {
                        continue;
                    }
                    const auto labelWithColon = i18nc("interpunctation for labels", "%1:", attributeLabel);
                    const auto &[it, inserted] = smimeAttributeFields.try_emplace(attribute, std::make_unique<InfoField>(labelWithColon, parent));
                    if (inserted) {
                        row++;
                        const auto &field = it->second;
                        gridLayout->addWidget(field->label(), row, 0);
                        gridLayout->addLayout(field->layout(), row, 1);
                    }
                }

                row++;
                smimeTrustLevelField = std::make_unique<InfoField>(i18n("Trust level:"), parent);
                gridLayout->addWidget(smimeTrustLevelField->label(), row, 0);
                gridLayout->addLayout(smimeTrustLevelField->layout(), row, 1);

                row++;
                validFromField = std::make_unique<InfoField>(i18n("Valid from:"), parent);
                gridLayout->addWidget(validFromField->label(), row, 0);
                gridLayout->addLayout(validFromField->layout(), row, 1);

                row++;
                expiresField = std::make_unique<InfoField>(i18n("Valid until:"), parent);
                changeExpirationAction = new QAction{parent};
                changeExpirationAction->setIcon(QIcon::fromTheme(QStringLiteral("editor")));
                changeExpirationAction->setToolTip(i18nc("@info:tooltip", "Change the end of the validity period"));
                Kleo::setAccessibleName(changeExpirationAction, i18nc("@action:button", "Change Validity"));
                expiresField->setAction(changeExpirationAction);
                gridLayout->addWidget(expiresField->label(), row, 0);
                gridLayout->addLayout(expiresField->layout(), row, 1);

                row++;
                statusField = std::make_unique<InfoField>(i18n("Status:"), parent);
                gridLayout->addWidget(statusField->label(), row, 0);
                gridLayout->addLayout(statusField->layout(), row, 1);

                row++;
                fingerprintField = std::make_unique<InfoField>(i18n("Fingerprint:"), parent);
                if (QGuiApplication::clipboard()) {
                    copyFingerprintAction = new QAction{parent};
                    copyFingerprintAction->setIcon(QIcon::fromTheme(QStringLiteral("edit-copy")));
                    copyFingerprintAction->setToolTip(i18nc("@info:tooltip", "Copy the fingerprint to the clipboard"));
                    Kleo::setAccessibleName(copyFingerprintAction, i18nc("@action:button", "Copy fingerprint"));
                    fingerprintField->setAction(copyFingerprintAction);
                }
                gridLayout->addWidget(fingerprintField->label(), row, 0);
                gridLayout->addLayout(fingerprintField->layout(), row, 1);

                row++;
                smimeIssuerField = std::make_unique<InfoField>(i18n("Issuer:"), parent);
                showIssuerCertificateAction = new QAction{parent};
                showIssuerCertificateAction->setIcon(QIcon::fromTheme(QStringLiteral("dialog-information")));
                showIssuerCertificateAction->setToolTip(i18nc("@info:tooltip", "Show the issuer certificate"));
                Kleo::setAccessibleName(showIssuerCertificateAction, i18nc("@action:button", "Show certificate"));
                smimeIssuerField->setAction(showIssuerCertificateAction);
                gridLayout->addWidget(smimeIssuerField->label(), row, 0);
                gridLayout->addLayout(smimeIssuerField->layout(), row, 1);

                row++;
                complianceField = std::make_unique<InfoField>(i18n("Compliance:"), parent);
                gridLayout->addWidget(complianceField->label(), row, 0);
                gridLayout->addLayout(complianceField->layout(), row, 1);

                row++;
                usageField = std::make_unique<InfoField>(i18n("Usage:"), parent);
                gridLayout->addWidget(usageField->label(), row, 0);
                gridLayout->addLayout(usageField->layout(), row, 1);

                row++;
                trustedIntroducerField = std::make_unique<InfoField>(i18n("Trusted introducer for:"), parent);
                gridLayout->addWidget(trustedIntroducerField->label(), row, 0);
                trustedIntroducerField->setToolTip(i18nc("@info:tooltip", "See certifications for details."));
                gridLayout->addLayout(trustedIntroducerField->layout(), row, 1);

                row++;
                privateKeyInfoField = std::make_unique<InfoField>(i18n("Private Key:"), parent);
                gridLayout->addWidget(privateKeyInfoField->label(), row, 0);
                gridLayout->addLayout(privateKeyInfoField->layout(), row, 1);

                mainLayout->addLayout(gridLayout);
            }

            tabWidget = new QTabWidget(parent);
            tabWidget->setDocumentMode(true); // we don't want a frame around the page widgets
            tabWidget->tabBar()->setDrawBase(false); // only draw the tabs

            mainLayout->addWidget(tabWidget);

            userIDs = new UserIdsWidget(parent);

            tabWidget->addTab(userIDs, i18nc("@title:tab", "User IDs"));
            smimeAddressList = new QListWidget{parent};
            // Breeze draws no frame for scroll areas that are the only widget in a layout...unless we force it
            smimeAddressList->setProperty("_breeze_force_frame", true);
            smimeAddressList->setAccessibleName(i18n("Related addresses"));
            smimeAddressList->setEditTriggers(QAbstractItemView::NoEditTriggers);
            smimeAddressList->setSelectionMode(QAbstractItemView::SingleSelection);
            tabWidget->addTab(smimeAddressList, i18nc("@title:tab", "Related Addresses"));

            subKeysWidget = new SubKeysWidget(parent);
            tabWidget->addTab(subKeysWidget, i18nc("@title:tab", "Subkeys"));

            webOfTrustWidget = new WebOfTrustWidget(parent);
            tabWidget->addTab(webOfTrustWidget, i18nc("@title:tab", "Certifications"));

            trustChainWidget = new TrustChainWidget(parent);
            tabWidget->addTab(trustChainWidget, i18nc("@title:tab", "Trust Chain Details"));

            cardInfoTab = new CardInfoTab(parent);
            tabWidget->addTab(cardInfoTab, i18nc("@title:tab", "Smartcard"));

            certificateDumpWidget = new CertificateDumpWidget(parent);
            tabWidget->addTab(certificateDumpWidget, i18nc("@title:tab", "Certificate Dump"));

#if GPGME_VERSION_NUMBER >= 0x011800 // 1.24.0
            revokersWidget = new RevokersWidget(parent);
            const auto index = tabWidget->addTab(revokersWidget, i18nc("@title:tab", "Revokers"));
            tabWidget->setTabVisible(index, false);
#endif
        }
    } ui;
};

CertificateDetailsWidget::Private::Private(CertificateDetailsWidget *qq)
    : q{qq}
{
    ui.setupUi(q);

    connect(ui.changeExpirationAction, &QAction::triggered, q, [this]() {
        changeExpiration();
    });
    connect(ui.showIssuerCertificateAction, &QAction::triggered, q, [this]() {
        showIssuerCertificate();
    });
    if (ui.copyFingerprintAction) {
        connect(ui.copyFingerprintAction, &QAction::triggered, q, [this]() {
            copyFingerprintToClipboard();
        });
    }

    connect(Kleo::KeyCache::instance().get(), &Kleo::KeyCache::keysMayHaveChanged, q, [this]() {
        keysMayHaveChanged();
    });
    connect(ui.userIDs, &UserIdsWidget::updateKey, q, [this]() {
        updateKey();
    });
}

void CertificateDetailsWidget::Private::setupCommonProperties()
{
    const bool isOpenPGP = key.protocol() == GpgME::OpenPGP;
    const bool isSMIME = key.protocol() == GpgME::CMS;
    const bool isOwnKey = key.hasSecret();

    for (const auto &[_, field] : ui.smimeAttributeFields) {
        field->setVisible(isSMIME);
    }
    ui.smimeTrustLevelField->setVisible(isSMIME);
    // ui.validFromField->setVisible(true); // always visible
    // ui.expiresField->setVisible(true); // always visible
    if (isOpenPGP && isOwnKey) {
        ui.expiresField->setAction(ui.changeExpirationAction);
    } else {
        ui.expiresField->setAction(nullptr);
    }
    // ui.fingerprintField->setVisible(true); // always visible
    ui.smimeIssuerField->setVisible(isSMIME);
    ui.complianceField->setVisible(DeVSCompliance::isCompliant());
    ui.trustedIntroducerField->setVisible(isOpenPGP); // may be hidden again by setupPGPProperties()

    // update availability of buttons
    ui.changeExpirationAction->setEnabled(canBeUsedForSecretKeyOperations(key));

    // update values of protocol-independent UI elements
    ui.validFromField->setValue(Formatting::creationDateString(key), Formatting::accessibleCreationDate(key));
    ui.expiresField->setValue(Formatting::expirationDateString(key, i18nc("Valid until:", "unlimited")), Formatting::accessibleExpirationDate(key));
    ui.fingerprintField->setValue(Formatting::prettyID(key.primaryFingerprint()), Formatting::accessibleHexID(key.primaryFingerprint()));
    ui.statusField->setValue(Formatting::complianceStringShort(key));

    QString storage;
    const auto &subkey = key.subkey(0);
    if (!key.hasSecret()) {
        storage = i18nc("not applicable", "n/a");
    } else if (key.subkey(0).isCardKey()) {
        if (const char *serialNo = subkey.cardSerialNumber()) {
            storage = i18nc("As in 'this secret key is stored on smart card <serial number>'", "smart card %1", QString::fromUtf8(serialNo));
        } else {
            storage = i18nc("As in 'this secret key is stored on a smart card'", "smart card");
        }
    } else if (!subkey.isSecret()) {
        storage = i18nc("key is 'offline key', i.e. secret key is not stored on this computer", "offline");
    } else if (KeyCache::instance()->cardsForSubkey(subkey).size() > 0) {
        storage = i18ncp("As in 'this key is stored on this computer and on smart card(s)'",
                         "On this computer and on a smart card",
                         "On this computer and on %1 smart cards",
                         KeyCache::instance()->cardsForSubkey(subkey).size());
    } else {
        storage = i18nc("As in 'this secret key is stored on this computer'", "on this computer");
    }
    ui.privateKeyInfoField->setValue(storage);
    if (DeVSCompliance::isCompliant()) {
        ui.complianceField->setValue(Kleo::Formatting::complianceStringForKey(key));
    }

    ui.usageField->setVisible(key.protocol() == GpgME::CMS);

    QStringList usage;

    if (subkey.canEncrypt()) {
        usage += i18n("encryption");
    }
    if (subkey.canSign()) {
        usage += i18n("signing");
    }
    if (subkey.canCertify()) {
        usage += i18n("certification");
    }
    if (subkey.canAuthenticate()) {
        usage += i18n("authentication");
    }
    if (subkey.isQualified()) {
        usage += i18nc("as in: can be used for ...", "qualified signatures");
    }

    ui.usageField->setValue(usage.join(i18nc("Separator between words in a list", ", ")));
    ui.cardInfoTab->setKey(key);
}

void CertificateDetailsWidget::Private::setUpSMIMEAdressList()
{
    ui.smimeAddressList->clear();

    const auto *const emailField = attributeField(QStringLiteral("EMAIL"));

    // add email address from primary user ID if not listed already as attribute field
    if (!emailField) {
        const auto ownerId = key.userID(0);
        const Kleo::DN dn(ownerId.id());
        const QString dnEmail = dn[QStringLiteral("EMAIL")];
        if (!dnEmail.isEmpty()) {
            ui.smimeAddressList->addItem(dnEmail);
        }
    }

    if (key.numUserIDs() > 1) {
        // iterate over the secondary user IDs
#ifdef USE_RANGES
        for (const auto uids = key.userIDs(); const auto &uid : std::ranges::subrange(std::next(uids.begin()), uids.end())) {
#else
        const auto uids = key.userIDs();
        for (auto it = std::next(uids.begin()); it != uids.end(); ++it) {
            const auto &uid = *it;
#endif
            const auto name = Kleo::Formatting::prettyName(uid);
            const auto email = Kleo::Formatting::prettyEMail(uid);
            QString itemText;
            if (name.isEmpty() && !email.isEmpty()) {
                // skip email addresses already listed in email attribute field
                if (emailField && email == emailField->value()) {
                    continue;
                }
                itemText = email;
            } else {
                // S/MIME certificates sometimes contain urls where both
                // name and mail is empty. In that case we print whatever
                // the uid is as name.
                //
                // Can be ugly like (3:uri24:http://ca.intevation.org), but
                // this is better then showing an empty entry.
                itemText = QString::fromUtf8(uid.id());
            }
            // avoid duplicate entries in the list
            if (ui.smimeAddressList->findItems(itemText, Qt::MatchExactly).empty()) {
                ui.smimeAddressList->addItem(itemText);
            }
        }
    }

    if (ui.smimeAddressList->count() == 0) {
        ui.tabWidget->setTabVisible(1, false);
    }
}

void CertificateDetailsWidget::Private::changeExpiration()
{
    auto cmd = new Kleo::Commands::ChangeExpiryCommand(key);
    QObject::connect(cmd, &Kleo::Commands::ChangeExpiryCommand::finished, q, [this]() {
        ui.changeExpirationAction->setEnabled(true);
    });
    ui.changeExpirationAction->setEnabled(false);
    cmd->start();
}

namespace
{
void ensureThatKeyDetailsAreLoaded(GpgME::Key &key)
{
    if (key.userID(0).numSignatures() == 0) {
        key.update();
    }
}
}

void CertificateDetailsWidget::Private::keysMayHaveChanged()
{
    auto newKey = Kleo::KeyCache::instance()->findByFingerprint(key.primaryFingerprint());
    if (!newKey.isNull()) {
        ensureThatKeyDetailsAreLoaded(newKey);
        setUpdatedKey(newKey);
    }
}

QIcon CertificateDetailsWidget::Private::trustLevelIcon(const GpgME::UserID &uid) const
{
    if (updateInProgress) {
        return QIcon::fromTheme(QStringLiteral("emblem-question"));
    }
    switch (uid.validity()) {
    case GpgME::UserID::Unknown:
    case GpgME::UserID::Undefined:
        return QIcon::fromTheme(QStringLiteral("emblem-question"));
    case GpgME::UserID::Never:
        return QIcon::fromTheme(QStringLiteral("emblem-error"));
    case GpgME::UserID::Marginal:
        return QIcon::fromTheme(QStringLiteral("emblem-warning"));
    case GpgME::UserID::Full:
    case GpgME::UserID::Ultimate:
        return QIcon::fromTheme(QStringLiteral("emblem-success"));
    }
    return {};
}

QString CertificateDetailsWidget::Private::trustLevelText(const GpgME::UserID &uid) const
{
    return updateInProgress ? i18n("Updating...") : Formatting::validityShort(uid);
}

namespace
{
auto isGood(const GpgME::UserID::Signature &signature)
{
    return signature.status() == GpgME::UserID::Signature::NoError //
        && !signature.isInvalid() //
        && 0x10 <= signature.certClass() && signature.certClass() <= 0x13;
}

auto accumulateTrustDomains(const std::vector<GpgME::UserID::Signature> &signatures)
{
    return std::accumulate(std::begin(signatures), std::end(signatures), std::set<QString>(), [](auto domains, const auto &signature) {
        if (isGood(signature) && signature.isTrustSignature()) {
            domains.insert(Formatting::trustSignatureDomain(signature));
        }
        return domains;
    });
}

auto accumulateTrustDomains(const std::vector<GpgME::UserID> &userIds)
{
    return std::accumulate(std::begin(userIds), std::end(userIds), std::set<QString>(), [](auto domains, const auto &userID) {
        const auto newDomains = accumulateTrustDomains(userID.signatures());
        std::copy(std::begin(newDomains), std::end(newDomains), std::inserter(domains, std::end(domains)));
        return domains;
    });
}
}

void CertificateDetailsWidget::Private::setTabVisible(QWidget *tab, bool visible)
{
    ui.tabWidget->setTabVisible(ui.tabWidget->indexOf(tab), visible);
}

void CertificateDetailsWidget::Private::setupPGPProperties()
{
    setTabVisible(ui.userIDs, true);
    setTabVisible(ui.smimeAddressList, false);
    setTabVisible(ui.subKeysWidget, true);
    setTabVisible(ui.webOfTrustWidget, true);
    setTabVisible(ui.trustChainWidget, false);
    setTabVisible(ui.certificateDumpWidget, false);

    ui.userIDs->setKey(key);
    ui.subKeysWidget->setKey(key);
    ui.webOfTrustWidget->setKey(key);
#if GPGME_VERSION_NUMBER >= 0x011800 // 1.24.0
    ui.revokersWidget->setKey(key);
    setTabVisible(ui.revokersWidget, key.numRevocationKeys() > 0);
#endif

    const auto trustDomains = accumulateTrustDomains(key.userIDs());
    ui.trustedIntroducerField->setVisible(!trustDomains.empty());
    ui.trustedIntroducerField->setValue(QStringList(std::begin(trustDomains), std::end(trustDomains)).join(u", "));

    ui.primaryUserIdField->setValue(Formatting::prettyUserID(key.userID(0)));
    ui.primaryUserIdField->setVisible(true);
}

static QString formatDNToolTip(const Kleo::DN &dn)
{
    QString html = QStringLiteral("<table border=\"0\" cell-spacing=15>");

    const auto appendRow = [&html, dn](const QString &lbl, const QString &attr) {
        const QString val = dn[attr];
        if (!val.isEmpty()) {
            html += QStringLiteral(
                        "<tr><th style=\"text-align: left; white-space: nowrap\">%1:</th>"
                        "<td style=\"white-space: nowrap\">%2</td>"
                        "</tr>")
                        .arg(lbl, val);
        }
    };
    appendRow(i18n("Common Name"), QStringLiteral("CN"));
    appendRow(i18n("Organization"), QStringLiteral("O"));
    appendRow(i18n("Street"), QStringLiteral("STREET"));
    appendRow(i18n("City"), QStringLiteral("L"));
    appendRow(i18n("State"), QStringLiteral("ST"));
    appendRow(i18n("Country"), QStringLiteral("C"));
    html += QStringLiteral("</table>");

    return html;
}

void CertificateDetailsWidget::Private::setupSMIMEProperties()
{
    setTabVisible(ui.userIDs, false);
    setTabVisible(ui.smimeAddressList, true);
    setTabVisible(ui.subKeysWidget, false);
    setTabVisible(ui.webOfTrustWidget, false);
    setTabVisible(ui.trustChainWidget, true);
    setTabVisible(ui.certificateDumpWidget, true);

    ui.trustChainWidget->setKey(key);
    const auto ownerId = key.userID(0);
    const Kleo::DN dn(ownerId.id());

    for (const auto &[attributeName, field] : ui.smimeAttributeFields) {
        const QString attributeValue = dn[attributeName];
        field->setValue(attributeValue);
        field->setVisible(!attributeValue.isEmpty());
    }
    ui.smimeTrustLevelField->setIcon(trustLevelIcon(ownerId));
    ui.smimeTrustLevelField->setValue(trustLevelText(ownerId));

    const Kleo::DN issuerDN(key.issuerName());
    const QString issuerCN = issuerDN[QStringLiteral("CN")];
    const QString issuer = issuerCN.isEmpty() ? QString::fromUtf8(key.issuerName()) : issuerCN;
    ui.smimeIssuerField->setValue(issuer);
    ui.smimeIssuerField->setToolTip(formatDNToolTip(issuerDN));
    ui.showIssuerCertificateAction->setEnabled(!key.isRoot());

    ui.primaryUserIdField->setVisible(false);

    ui.certificateDumpWidget->setKey(key);

    setUpSMIMEAdressList();
}

void CertificateDetailsWidget::Private::showIssuerCertificate()
{
    // there is either one or no parent key
    const auto parentKeys = KeyCache::instance()->findIssuers(key, KeyCache::NoOption);

    if (parentKeys.empty()) {
        KMessageBox::error(q, i18n("The issuer certificate could not be found locally."));
        return;
    }
    auto cmd = new Kleo::Commands::DetailsCommand(parentKeys.front());
    cmd->setParentWidget(q);
    cmd->start();
}

void CertificateDetailsWidget::Private::copyFingerprintToClipboard()
{
    if (auto clipboard = QGuiApplication::clipboard()) {
        clipboard->setText(QString::fromLatin1(key.primaryFingerprint()));
    }
}

CertificateDetailsWidget::CertificateDetailsWidget(QWidget *parent)
    : QWidget{parent}
    , d{std::make_unique<Private>(this)}
{
}

CertificateDetailsWidget::~CertificateDetailsWidget() = default;

void CertificateDetailsWidget::Private::keyListDone(const GpgME::KeyListResult &, const std::vector<GpgME::Key> &keys, const QString &, const GpgME::Error &)
{
    setUpdateInProgress(false);
    if (keys.size() != 1) {
        qCWarning(KLEOPATRA_LOG) << "Invalid keylist result in update.";
        return;
    }
    // As we listen for keysmayhavechanged we get the update
    // after updating the keycache.
    KeyCache::mutableInstance()->insert(keys);
}

void CertificateDetailsWidget::Private::updateKey()
{
    key.update();
    setUpdatedKey(key);
}

void CertificateDetailsWidget::Private::setUpdatedKey(const GpgME::Key &k)
{
    key = k;

    setupCommonProperties();
    if (key.protocol() == GpgME::OpenPGP) {
        setupPGPProperties();
    } else {
        setupSMIMEProperties();
    }
}

void CertificateDetailsWidget::setKey(const GpgME::Key &key)
{
    if (key.protocol() == GpgME::CMS) {
        // For everything but S/MIME this should be quick
        // and we don't need to show another status.
        d->setUpdateInProgress(true);
    }
    d->setUpdatedKey(key);

    // Run a keylistjob with full details (TOFU / Validate)
    QGpgME::KeyListJob *job =
        key.protocol() == GpgME::OpenPGP ? QGpgME::openpgp()->keyListJob(false, true, true) : QGpgME::smime()->keyListJob(false, true, true);

    auto ctx = QGpgME::Job::context(job);
    ctx->addKeyListMode(GpgME::WithTofu);
    ctx->addKeyListMode(GpgME::SignatureNotations);
    ctx->addKeyListMode(GpgME::WithKeygrip);
    if (key.hasSecret()) {
        ctx->addKeyListMode(GpgME::WithSecret);
    }

    // Windows QGpgME new style connect problem makes this necessary.
    connect(job,
            SIGNAL(result(GpgME::KeyListResult, std::vector<GpgME::Key>, QString, GpgME::Error)),
            this,
            SLOT(keyListDone(GpgME::KeyListResult, std::vector<GpgME::Key>, QString, GpgME::Error)));

    job->start(QStringList() << QLatin1StringView(key.primaryFingerprint()));
}

GpgME::Key CertificateDetailsWidget::key() const
{
    return d->key;
}

void CertificateDetailsWidget::Private::setUpdateInProgress(bool updateInProgress)
{
    this->updateInProgress = updateInProgress;
    ui.userIDs->setUpdateInProgress(updateInProgress);
}

#include "moc_certificatedetailswidget.cpp"
