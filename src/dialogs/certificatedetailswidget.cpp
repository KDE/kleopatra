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

#include "exportdialog.h"
#include "kleopatra_debug.h"
#include "subkeyswidget.h"
#include "trustchainwidget.h"
#include "weboftrustdialog.h"

#include "commands/certifycertificatecommand.h"
#include "commands/changeexpirycommand.h"
#include "commands/changepassphrasecommand.h"
#ifdef MAILAKONADI_ENABLED
#include "commands/exportopenpgpcerttoprovidercommand.h"
#endif // MAILAKONADI_ENABLED
#include "commands/addadskcommand.h"
#include "commands/adduseridcommand.h"
#include "commands/detailscommand.h"
#include "commands/dumpcertificatecommand.h"
#include "commands/genrevokecommand.h"
#include "commands/refreshcertificatecommand.h"
#include "commands/revokecertificationcommand.h"
#include "commands/revokeuseridcommand.h"
#include "commands/setprimaryuseridcommand.h"
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
#include <Libkleo/NavigatableTreeWidget>

#include <KLocalizedString>
#include <KMessageBox>
#include <KSeparator>

#include <gpgme++/context.h>
#include <gpgme++/key.h>
#include <gpgme++/keylistresult.h>
#include <gpgme++/tofuinfo.h>

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

namespace
{
std::vector<GpgME::UserID> selectedUserIDs(const QTreeWidget *treeWidget)
{
    if (!treeWidget) {
        return {};
    }

    std::vector<GpgME::UserID> userIDs;
    const auto selected = treeWidget->selectedItems();
    std::transform(selected.begin(), selected.end(), std::back_inserter(userIDs), [](const QTreeWidgetItem *item) {
        return item->data(0, Qt::UserRole).value<GpgME::UserID>();
    });
    return userIDs;
}
}

class CertificateDetailsWidget::Private
{
public:
    Private(CertificateDetailsWidget *qq);

    void setupCommonProperties();
    void updateUserIDActions();
    void setUpUserIDTable();
    void setUpSMIMEAdressList();
    void setupPGPProperties();
    void setupSMIMEProperties();

    void revokeUserID(const GpgME::UserID &uid);
    void revokeSelectedUserID();
    void genRevokeCert();
    void refreshCertificate();
    void certifyUserIDs();
    void revokeCertifications();
    void webOfTrustClicked();
    void exportClicked();
    void addUserID();
    void setPrimaryUserID(const GpgME::UserID &uid = {});
    void changePassphrase();
    void changeExpiration();
    void keysMayHaveChanged();
    void showTrustChainDialog();
    void showMoreDetails();
    void userIDTableContextMenuRequested(const QPoint &p);

    QString tofuTooltipString(const GpgME::UserID &uid) const;
    QIcon trustLevelIcon(const GpgME::UserID &uid) const;
    QString trustLevelText(const GpgME::UserID &uid) const;

    void showIssuerCertificate();

    void updateKey();
    void setUpdatedKey(const GpgME::Key &key);
    void keyListDone(const GpgME::KeyListResult &, const std::vector<GpgME::Key> &, const QString &, const GpgME::Error &);
    void copyFingerprintToClipboard();

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
        QWidget *userIDs = nullptr;
        QLabel *userIDTableLabel = nullptr;
        NavigatableTreeWidget *userIDTable = nullptr;
        QPushButton *addUserIDBtn = nullptr;
        QPushButton *setPrimaryUserIDBtn = nullptr;
        QPushButton *certifyBtn = nullptr;
        QPushButton *revokeCertificationsBtn = nullptr;
        QPushButton *revokeUserIDBtn = nullptr;
        QPushButton *webOfTrustBtn = nullptr;

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

        QLabel *smimeRelatedAddresses = nullptr;
        QListWidget *smimeAddressList = nullptr;

        QPushButton *moreDetailsBtn = nullptr;
        QPushButton *trustChainDetailsBtn = nullptr;
        QPushButton *refreshBtn = nullptr;
        QPushButton *changePassphraseBtn = nullptr;
        QPushButton *exportBtn = nullptr;
        QPushButton *genRevokeBtn = nullptr;
        QPushButton *addADSKBtn = nullptr;

        void setupUi(QWidget *parent)
        {
            auto mainLayout = new QVBoxLayout{parent};

            userIDs = new QWidget{parent};
            {
                auto userIDsLayout = new QVBoxLayout{userIDs};
                userIDsLayout->setContentsMargins({});

                userIDTableLabel = new QLabel(i18n("User IDs:"), parent);
                userIDsLayout->addWidget(userIDTableLabel);

                userIDTable = new NavigatableTreeWidget{parent};
                userIDTableLabel->setBuddy(userIDTable);
                userIDTable->setAccessibleName(i18n("User IDs"));
                QTreeWidgetItem *__qtreewidgetitem = new QTreeWidgetItem();
                __qtreewidgetitem->setText(0, QString::fromUtf8("1"));
                userIDTable->setHeaderItem(__qtreewidgetitem);
                userIDTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
                userIDTable->setSelectionMode(QAbstractItemView::ExtendedSelection);
                userIDTable->setRootIsDecorated(false);
                userIDTable->setUniformRowHeights(true);
                userIDTable->setAllColumnsShowFocus(false);

                userIDsLayout->addWidget(userIDTable);

                {
                    auto buttonRow = new QHBoxLayout;

                    addUserIDBtn = new QPushButton(i18nc("@action:button", "Add User ID"), parent);
                    buttonRow->addWidget(addUserIDBtn);

                    setPrimaryUserIDBtn = new QPushButton{i18nc("@action:button", "Flag as Primary"), parent};
                    setPrimaryUserIDBtn->setToolTip(i18nc("@info:tooltip", "Flag the selected user ID as the primary user ID of this key."));
                    buttonRow->addWidget(setPrimaryUserIDBtn);

                    certifyBtn = new QPushButton(i18nc("@action:button", "Certify User IDs"), parent);
                    buttonRow->addWidget(certifyBtn);

                    webOfTrustBtn = new QPushButton(i18nc("@action:button", "Show Certifications"), parent);
                    buttonRow->addWidget(webOfTrustBtn);

                    revokeCertificationsBtn = new QPushButton(i18nc("@action:button", "Revoke Certifications"), parent);
                    buttonRow->addWidget(revokeCertificationsBtn);

                    revokeUserIDBtn = new QPushButton(i18nc("@action:button", "Revoke User ID"), parent);
                    buttonRow->addWidget(revokeUserIDBtn);

                    addADSKBtn =
                        new QPushButton(i18nc("@action:button 'ADSK' means 'Additional Decryption Subkey'; Don't try translating it, though.", "Add ADSK"),
                                        parent);
                    addADSKBtn->setVisible(false);
                    buttonRow->addWidget(addADSKBtn);
                    buttonRow->addStretch(1);

                    userIDsLayout->addLayout(buttonRow);
                }

                userIDsLayout->addWidget(new KSeparator{Qt::Horizontal, parent});
            }

            mainLayout->addWidget(userIDs);

            {
                auto gridLayout = new QGridLayout;
                gridLayout->setColumnStretch(1, 1);

                int row = -1;
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
                trustedIntroducerField = std::make_unique<InfoField>(i18n("Trusted introducer for:"), parent);
                gridLayout->addWidget(trustedIntroducerField->label(), row, 0);
                trustedIntroducerField->setToolTip(i18n("See certifications for details."));
                gridLayout->addLayout(trustedIntroducerField->layout(), row, 1);

                mainLayout->addLayout(gridLayout);
            }

            smimeRelatedAddresses = new QLabel(i18n("Related addresses:"), parent);
            mainLayout->addWidget(smimeRelatedAddresses);

            smimeAddressList = new QListWidget{parent};
            smimeRelatedAddresses->setBuddy(smimeAddressList);
            smimeAddressList->setAccessibleName(i18n("Related addresses"));
            smimeAddressList->setEditTriggers(QAbstractItemView::NoEditTriggers);
            smimeAddressList->setSelectionMode(QAbstractItemView::SingleSelection);

            mainLayout->addWidget(smimeAddressList);

            mainLayout->addStretch();

            {
                auto buttonRow = new QHBoxLayout;

                moreDetailsBtn = new QPushButton(i18nc("@action:button", "More Details..."), parent);
                buttonRow->addWidget(moreDetailsBtn);

                trustChainDetailsBtn = new QPushButton(i18nc("@action:button", "Trust Chain Details"), parent);
                buttonRow->addWidget(trustChainDetailsBtn);

                refreshBtn = new QPushButton{i18nc("@action:button", "Update"), parent};
                buttonRow->addWidget(refreshBtn);

                exportBtn = new QPushButton(i18nc("@action:button", "Export"), parent);
                buttonRow->addWidget(exportBtn);

                changePassphraseBtn = new QPushButton(i18nc("@action:button", "Change Passphrase"), parent);
                buttonRow->addWidget(changePassphraseBtn);

                genRevokeBtn = new QPushButton(i18nc("@action:button", "Generate Revocation Certificate"), parent);
                genRevokeBtn->setToolTip(u"<html>"
                                         % i18n("A revocation certificate is a file that serves as a \"kill switch\" to publicly "
                                                "declare that a key shall not anymore be used.  It is not possible "
                                                "to retract such a revocation certificate once it has been published.")
                                         % u"</html>");
                buttonRow->addWidget(genRevokeBtn);

                buttonRow->addStretch(1);

                mainLayout->addLayout(buttonRow);
            }
        }
    } ui;
};

CertificateDetailsWidget::Private::Private(CertificateDetailsWidget *qq)
    : q{qq}
{
    ui.setupUi(q);

    ui.userIDTable->setContextMenuPolicy(Qt::CustomContextMenu);
    connect(ui.userIDTable, &QAbstractItemView::customContextMenuRequested, q, [this](const QPoint &p) {
        userIDTableContextMenuRequested(p);
    });
    connect(ui.userIDTable, &QTreeWidget::itemSelectionChanged, q, [this]() {
        updateUserIDActions();
    });
    connect(ui.addUserIDBtn, &QPushButton::clicked, q, [this]() {
        addUserID();
    });
    connect(ui.setPrimaryUserIDBtn, &QPushButton::clicked, q, [this]() {
        setPrimaryUserID();
    });
    connect(ui.revokeUserIDBtn, &QPushButton::clicked, q, [this]() {
        revokeSelectedUserID();
    });
    connect(ui.changePassphraseBtn, &QPushButton::clicked, q, [this]() {
        changePassphrase();
    });
    connect(ui.genRevokeBtn, &QPushButton::clicked, q, [this]() {
        genRevokeCert();
    });
    connect(ui.changeExpirationAction, &QAction::triggered, q, [this]() {
        changeExpiration();
    });
    connect(ui.showIssuerCertificateAction, &QAction::triggered, q, [this]() {
        showIssuerCertificate();
    });
    connect(ui.trustChainDetailsBtn, &QPushButton::pressed, q, [this]() {
        showTrustChainDialog();
    });
    connect(ui.moreDetailsBtn, &QPushButton::pressed, q, [this]() {
        showMoreDetails();
    });
    connect(ui.refreshBtn, &QPushButton::clicked, q, [this]() {
        refreshCertificate();
    });
    connect(ui.certifyBtn, &QPushButton::clicked, q, [this]() {
        certifyUserIDs();
    });
    connect(ui.revokeCertificationsBtn, &QPushButton::clicked, q, [this]() {
        revokeCertifications();
    });
    connect(ui.webOfTrustBtn, &QPushButton::clicked, q, [this]() {
        webOfTrustClicked();
    });
    connect(ui.exportBtn, &QPushButton::clicked, q, [this]() {
        exportClicked();
    });
    if (ui.copyFingerprintAction) {
        connect(ui.copyFingerprintAction, &QAction::triggered, q, [this]() {
            copyFingerprintToClipboard();
        });
    }

    connect(Kleo::KeyCache::instance().get(), &Kleo::KeyCache::keysMayHaveChanged, q, [this]() {
        keysMayHaveChanged();
    });
    connect(ui.addADSKBtn, &QPushButton::clicked, q, [this]() {
        auto addADSKCommand = new Kleo::Commands::AddADSKCommand(q->key());
        addADSKCommand->setParentWidget(q);
        addADSKCommand->start();
    });
}

void CertificateDetailsWidget::Private::setupCommonProperties()
{
    const bool isOpenPGP = key.protocol() == GpgME::OpenPGP;
    const bool isSMIME = key.protocol() == GpgME::CMS;
    const bool isOwnKey = key.hasSecret();
    const auto isLocalKey = !isRemoteKey(key);
    const auto keyCanBeCertified = Kleo::canBeCertified(key);

    // update visibility of UI elements
    ui.userIDs->setVisible(isOpenPGP);
    ui.addUserIDBtn->setVisible(isOwnKey);
    ui.setPrimaryUserIDBtn->setVisible(isOwnKey);
    // ui.certifyBtn->setVisible(true); // always visible (for OpenPGP keys)
    // ui.webOfTrustBtn->setVisible(true); // always visible (for OpenPGP keys)
    ui.revokeCertificationsBtn->setVisible(Kleo::Commands::RevokeCertificationCommand::isSupported());
    ui.revokeUserIDBtn->setVisible(isOwnKey);

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

    ui.smimeRelatedAddresses->setVisible(isSMIME);
    ui.smimeAddressList->setVisible(isSMIME);

    ui.moreDetailsBtn->setVisible(isLocalKey);
    ui.moreDetailsBtn->setText(isSMIME        ? i18nc("@action:button", "More Details...")
                                   : isOwnKey ? i18nc("@action:button", "Manage Subkeys")
                                              : i18nc("@action:button", "Show Subkeys"));

    ui.trustChainDetailsBtn->setVisible(isSMIME);
    ui.refreshBtn->setVisible(isLocalKey);
    ui.changePassphraseBtn->setVisible(isSecretKeyStoredInKeyRing(key));
    ui.exportBtn->setVisible(isLocalKey);
    ui.genRevokeBtn->setVisible(isOpenPGP && isOwnKey);

    // update availability of buttons
    const auto userCanSignUserIDs = userHasCertificationKey();
    ui.addUserIDBtn->setEnabled(canBeUsedForSecretKeyOperations(key));
    ui.setPrimaryUserIDBtn->setEnabled(false); // requires a selected user ID
    ui.certifyBtn->setEnabled(isLocalKey && keyCanBeCertified && userCanSignUserIDs);
    ui.webOfTrustBtn->setEnabled(isLocalKey);
    ui.revokeCertificationsBtn->setEnabled(userCanSignUserIDs && isLocalKey);
    ui.revokeUserIDBtn->setEnabled(false); // requires a selected user ID
    ui.changeExpirationAction->setEnabled(canBeUsedForSecretKeyOperations(key));
    ui.changePassphraseBtn->setEnabled(isSecretKeyStoredInKeyRing(key));
    ui.genRevokeBtn->setEnabled(canBeUsedForSecretKeyOperations(key));

    // update values of protocol-independent UI elements
    ui.validFromField->setValue(Formatting::creationDateString(key), Formatting::accessibleCreationDate(key));
    ui.expiresField->setValue(Formatting::expirationDateString(key, i18nc("Valid until:", "unlimited")), Formatting::accessibleExpirationDate(key));
    ui.fingerprintField->setValue(Formatting::prettyID(key.primaryFingerprint()), Formatting::accessibleHexID(key.primaryFingerprint()));
    if (DeVSCompliance::isCompliant()) {
        ui.complianceField->setValue(Kleo::Formatting::complianceStringForKey(key));
    }
    ui.addADSKBtn->setVisible(key.protocol() == GpgME::OpenPGP && isOwnKey);
}

void CertificateDetailsWidget::Private::updateUserIDActions()
{
    const auto userIDs = selectedUserIDs(ui.userIDTable);
    const auto singleUserID = userIDs.size() == 1 ? userIDs.front() : GpgME::UserID{};
    const bool isPrimaryUserID = !singleUserID.isNull() && (ui.userIDTable->selectedItems().front() == ui.userIDTable->topLevelItem(0));
    ui.setPrimaryUserIDBtn->setEnabled(!singleUserID.isNull() //
                                       && !isPrimaryUserID //
                                       && !Kleo::isRevokedOrExpired(singleUserID) //
                                       && canBeUsedForSecretKeyOperations(key));
    ui.revokeUserIDBtn->setEnabled(!singleUserID.isNull() && canCreateCertifications(key) && canRevokeUserID(singleUserID));
}

void CertificateDetailsWidget::Private::setUpUserIDTable()
{
    ui.userIDTable->clear();

    QStringList headers = {i18n("Email"), i18n("Name"), i18n("Trust Level"), i18n("Tags")};
    ui.userIDTable->setColumnCount(headers.count());
    ui.userIDTable->setColumnWidth(0, 200);
    ui.userIDTable->setColumnWidth(1, 200);
    ui.userIDTable->setHeaderLabels(headers);

    const auto uids = key.userIDs();
    for (unsigned int i = 0; i < uids.size(); ++i) {
        const auto &uid = uids[i];
        auto item = new QTreeWidgetItem;
        const QString toolTip = tofuTooltipString(uid);
        item->setData(0, Qt::UserRole, QVariant::fromValue(uid));

        auto pMail = Kleo::Formatting::prettyEMail(uid);
        auto pName = Kleo::Formatting::prettyName(uid);

        item->setData(0, Qt::DisplayRole, pMail);
        item->setData(0, Qt::ToolTipRole, toolTip);
        item->setData(0, Qt::AccessibleTextRole, pMail.isEmpty() ? i18nc("text for screen readers for an empty email address", "no email") : pMail);
        item->setData(1, Qt::DisplayRole, pName);
        item->setData(1, Qt::ToolTipRole, toolTip);

        item->setData(2, Qt::DecorationRole, trustLevelIcon(uid));
        item->setData(2, Qt::DisplayRole, trustLevelText(uid));
        item->setData(2, Qt::ToolTipRole, toolTip);

        GpgME::Error err;
        QStringList tagList;
        for (const auto &tag : uid.remarks(Tags::tagKeys(), err)) {
            if (err) {
                qCWarning(KLEOPATRA_LOG) << "Getting remarks for user ID" << uid.id() << "failed:" << err;
            }
            tagList << QString::fromStdString(tag);
        }
        qCDebug(KLEOPATRA_LOG) << "tagList:" << tagList;
        const auto tags = tagList.join(QStringLiteral("; "));
        item->setData(3, Qt::DisplayRole, tags);
        item->setData(3, Qt::ToolTipRole, toolTip);

        ui.userIDTable->addTopLevelItem(item);
    }
    if (!Tags::tagsEnabled()) {
        ui.userIDTable->hideColumn(3);
    }
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
        ui.smimeRelatedAddresses->setVisible(false);
        ui.smimeAddressList->setVisible(false);
    }
}

void CertificateDetailsWidget::Private::revokeUserID(const GpgME::UserID &userId)
{
    const QString message =
        xi18nc("@info", "<para>Do you really want to revoke the user ID<nl/><emphasis>%1</emphasis> ?</para>", QString::fromUtf8(userId.id()));
    auto confirmButton = KStandardGuiItem::ok();
    confirmButton.setText(i18nc("@action:button", "Revoke User ID"));
    confirmButton.setToolTip({});
    const auto choice = KMessageBox::questionTwoActions(q->window(),
                                                        message,
                                                        i18nc("@title:window", "Confirm Revocation"),
                                                        confirmButton,
                                                        KStandardGuiItem::cancel(),
                                                        {},
                                                        KMessageBox::Notify | KMessageBox::WindowModal);
    if (choice != KMessageBox::ButtonCode::PrimaryAction) {
        return;
    }

    auto cmd = new Commands::RevokeUserIDCommand(userId);
    cmd->setParentWidget(q);
    connect(cmd, &Command::finished, q, [this]() {
        ui.userIDTable->setEnabled(true);
        // the Revoke User ID button will be updated by the key update
        updateKey();
    });
    ui.userIDTable->setEnabled(false);
    ui.revokeUserIDBtn->setEnabled(false);
    cmd->start();
}

void CertificateDetailsWidget::Private::revokeSelectedUserID()
{
    const auto userIDs = selectedUserIDs(ui.userIDTable);
    if (userIDs.size() != 1) {
        return;
    }
    revokeUserID(userIDs.front());
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

void CertificateDetailsWidget::Private::changePassphrase()
{
    auto cmd = new Kleo::Commands::ChangePassphraseCommand(key);
    QObject::connect(cmd, &Kleo::Commands::ChangePassphraseCommand::finished, q, [this]() {
        ui.changePassphraseBtn->setEnabled(true);
    });
    ui.changePassphraseBtn->setEnabled(false);
    cmd->start();
}

void CertificateDetailsWidget::Private::genRevokeCert()
{
    auto cmd = new Kleo::Commands::GenRevokeCommand(key);
    QObject::connect(cmd, &Kleo::Commands::GenRevokeCommand::finished, q, [this]() {
        ui.genRevokeBtn->setEnabled(true);
    });
    ui.genRevokeBtn->setEnabled(false);
    cmd->start();
}

void CertificateDetailsWidget::Private::refreshCertificate()
{
    auto cmd = new Kleo::RefreshCertificateCommand{key};
    QObject::connect(cmd, &Kleo::RefreshCertificateCommand::finished, q, [this]() {
        ui.refreshBtn->setEnabled(true);
    });
    ui.refreshBtn->setEnabled(false);
    cmd->start();
}

void CertificateDetailsWidget::Private::certifyUserIDs()
{
    const auto userIDs = selectedUserIDs(ui.userIDTable);
    auto cmd = userIDs.empty() ? new Kleo::Commands::CertifyCertificateCommand{key} //
                               : new Kleo::Commands::CertifyCertificateCommand{userIDs};
    QObject::connect(cmd, &Kleo::Commands::CertifyCertificateCommand::finished, q, [this]() {
        updateKey();
        ui.certifyBtn->setEnabled(true);
    });
    ui.certifyBtn->setEnabled(false);
    cmd->start();
}

void CertificateDetailsWidget::Private::revokeCertifications()
{
    const auto userIDs = selectedUserIDs(ui.userIDTable);
    auto cmd = userIDs.empty() ? new Kleo::Commands::RevokeCertificationCommand{key} //
                               : new Kleo::Commands::RevokeCertificationCommand{userIDs};
    QObject::connect(cmd, &Kleo::Command::finished, q, [this]() {
        updateKey();
        ui.revokeCertificationsBtn->setEnabled(true);
    });
    ui.revokeCertificationsBtn->setEnabled(false);
    cmd->start();
}

void CertificateDetailsWidget::Private::webOfTrustClicked()
{
    QScopedPointer<WebOfTrustDialog> dlg(new WebOfTrustDialog(q));
    dlg->setKey(key);
    dlg->exec();
}

void CertificateDetailsWidget::Private::exportClicked()
{
    QScopedPointer<ExportDialog> dlg(new ExportDialog(q));
    dlg->setKey(key);
    dlg->exec();
}

void CertificateDetailsWidget::Private::addUserID()
{
    auto cmd = new Kleo::Commands::AddUserIDCommand(key);
    QObject::connect(cmd, &Kleo::Commands::AddUserIDCommand::finished, q, [this]() {
        ui.addUserIDBtn->setEnabled(true);
        updateKey();
    });
    ui.addUserIDBtn->setEnabled(false);
    cmd->start();
}

void CertificateDetailsWidget::Private::setPrimaryUserID(const GpgME::UserID &uid)
{
    auto userId = uid;
    if (userId.isNull()) {
        const auto userIDs = selectedUserIDs(ui.userIDTable);
        if (userIDs.size() != 1) {
            return;
        }
        userId = userIDs.front();
    }

    auto cmd = new Kleo::Commands::SetPrimaryUserIDCommand(userId);
    QObject::connect(cmd, &Kleo::Commands::SetPrimaryUserIDCommand::finished, q, [this]() {
        ui.userIDTable->setEnabled(true);
        // the Flag As Primary button will be updated by the key update
        updateKey();
    });
    ui.userIDTable->setEnabled(false);
    ui.setPrimaryUserIDBtn->setEnabled(false);
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

void CertificateDetailsWidget::Private::showTrustChainDialog()
{
    QScopedPointer<TrustChainDialog> dlg(new TrustChainDialog(q));
    dlg->setKey(key);
    dlg->exec();
}

void CertificateDetailsWidget::Private::userIDTableContextMenuRequested(const QPoint &p)
{
    const auto userIDs = selectedUserIDs(ui.userIDTable);
    const auto singleUserID = (userIDs.size() == 1) ? userIDs.front() : GpgME::UserID{};
    const bool isPrimaryUserID = !singleUserID.isNull() && (ui.userIDTable->selectedItems().front() == ui.userIDTable->topLevelItem(0));
    const bool canSignUserIDs = userHasCertificationKey();
    const auto isLocalKey = !isRemoteKey(key);
    const auto keyCanBeCertified = Kleo::canBeCertified(key);

    auto menu = new QMenu(q);
    if (key.hasSecret()) {
        auto action =
            menu->addAction(QIcon::fromTheme(QStringLiteral("favorite")), i18nc("@action:inmenu", "Flag as Primary User ID"), q, [this, singleUserID]() {
                setPrimaryUserID(singleUserID);
            });
        action->setEnabled(!singleUserID.isNull() //
                           && !isPrimaryUserID //
                           && !Kleo::isRevokedOrExpired(singleUserID) //
                           && canBeUsedForSecretKeyOperations(key));
    }
    {
        const auto actionText = userIDs.empty() ? i18nc("@action:inmenu", "Certify User IDs...")
                                                : i18ncp("@action:inmenu", "Certify User ID...", "Certify User IDs...", userIDs.size());
        auto action = menu->addAction(QIcon::fromTheme(QStringLiteral("view-certificate-sign")), actionText, q, [this]() {
            certifyUserIDs();
        });
        action->setEnabled(isLocalKey && keyCanBeCertified && canSignUserIDs);
    }
    if (Kleo::Commands::RevokeCertificationCommand::isSupported()) {
        const auto actionText = userIDs.empty() ? i18nc("@action:inmenu", "Revoke Certifications...")
                                                : i18ncp("@action:inmenu", "Revoke Certification...", "Revoke Certifications...", userIDs.size());
        auto action = menu->addAction(QIcon::fromTheme(QStringLiteral("view-certificate-revoke")), actionText, q, [this]() {
            revokeCertifications();
        });
        action->setEnabled(isLocalKey && canSignUserIDs);
    }
#ifdef MAILAKONADI_ENABLED
    if (key.hasSecret()) {
        auto action = menu->addAction(QIcon::fromTheme(QStringLiteral("view-certificate-export")),
                                      i18nc("@action:inmenu", "Publish at Mail Provider ..."),
                                      q,
                                      [this, singleUserID]() {
                                          auto cmd = new Kleo::Commands::ExportOpenPGPCertToProviderCommand(singleUserID);
                                          ui.userIDTable->setEnabled(false);
                                          connect(cmd, &Kleo::Commands::ExportOpenPGPCertToProviderCommand::finished, q, [this]() {
                                              ui.userIDTable->setEnabled(true);
                                          });
                                          cmd->start();
                                      });
        action->setEnabled(!singleUserID.isNull());
    }
#endif // MAILAKONADI_ENABLED
    {
        auto action =
            menu->addAction(QIcon::fromTheme(QStringLiteral("view-certificate-revoke")), i18nc("@action:inmenu", "Revoke User ID"), q, [this, singleUserID]() {
                revokeUserID(singleUserID);
            });
        action->setEnabled(!singleUserID.isNull() && canCreateCertifications(key) && canRevokeUserID(singleUserID));
    }
    connect(menu, &QMenu::aboutToHide, menu, &QObject::deleteLater);
    menu->popup(ui.userIDTable->viewport()->mapToGlobal(p));
}

void CertificateDetailsWidget::Private::showMoreDetails()
{
    if (key.protocol() == GpgME::CMS) {
        auto cmd = new Kleo::Commands::DumpCertificateCommand(key);
        cmd->setParentWidget(q);
        cmd->setUseDialog(true);
        cmd->start();
    } else {
        auto dlg = new SubKeysDialog{q};
        dlg->setAttribute(Qt::WA_DeleteOnClose);
        dlg->setKey(key);
        dlg->open();
    }
}

QString CertificateDetailsWidget::Private::tofuTooltipString(const GpgME::UserID &uid) const
{
    const auto tofu = uid.tofuInfo();
    if (tofu.isNull()) {
        return QString();
    }

    QString html = QStringLiteral("<table border=\"0\" cell-padding=\"5\">");
    const auto appendRow = [&html](const QString &lbl, const QString &val) {
        html += QStringLiteral(
                    "<tr>"
                    "<th style=\"text-align: right; padding-right: 5px; white-space: nowrap;\">%1:</th>"
                    "<td style=\"white-space: nowrap;\">%2</td>"
                    "</tr>")
                    .arg(lbl, val);
    };
    const auto appendHeader = [this, &html](const QString &hdr) {
        html += QStringLiteral("<tr><th colspan=\"2\" style=\"background-color: %1; color: %2\">%3</th></tr>")
                    .arg(q->palette().highlight().color().name(), q->palette().highlightedText().color().name(), hdr);
    };
    const auto dateTime = [](long ts) {
        QLocale l;
        return ts == 0 ? i18n("never") : l.toString(QDateTime::fromSecsSinceEpoch(ts), QLocale::ShortFormat);
    };
    appendHeader(i18n("Signing"));
    appendRow(i18n("First message"), dateTime(tofu.signFirst()));
    appendRow(i18n("Last message"), dateTime(tofu.signLast()));
    appendRow(i18n("Message count"), QString::number(tofu.signCount()));
    appendHeader(i18n("Encryption"));
    appendRow(i18n("First message"), dateTime(tofu.encrFirst()));
    appendRow(i18n("Last message"), dateTime(tofu.encrLast()));
    appendRow(i18n("Message count"), QString::number(tofu.encrCount()));

    html += QStringLiteral("</table>");
    // Make sure the tooltip string is different for each UserID, even if the
    // data are the same, otherwise the tooltip is not updated and moved when
    // user moves mouse from one row to another.
    html += QStringLiteral("<!-- %1 //-->").arg(QString::fromUtf8(uid.id()));
    return html;
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

void CertificateDetailsWidget::Private::setupPGPProperties()
{
    setUpUserIDTable();

    const auto trustDomains = accumulateTrustDomains(key.userIDs());
    ui.trustedIntroducerField->setVisible(!trustDomains.empty());
    ui.trustedIntroducerField->setValue(QStringList(std::begin(trustDomains), std::end(trustDomains)).join(u", "));

    ui.refreshBtn->setToolTip(i18nc("@info:tooltip", "Update the key from external sources."));
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

    setUpSMIMEAdressList();

    ui.refreshBtn->setToolTip(i18nc("@info:tooltip", "Update the CRLs and do a full validation check of the certificate."));
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
    updateInProgress = false;
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
        d->updateInProgress = true;
    }
    d->setUpdatedKey(key);

    // Run a keylistjob with full details (TOFU / Validate)
    QGpgME::KeyListJob *job =
        key.protocol() == GpgME::OpenPGP ? QGpgME::openpgp()->keyListJob(false, true, true) : QGpgME::smime()->keyListJob(false, true, true);

    auto ctx = QGpgME::Job::context(job);
    ctx->addKeyListMode(GpgME::WithTofu);
    ctx->addKeyListMode(GpgME::SignatureNotations);
    if (key.hasSecret()) {
        ctx->addKeyListMode(GpgME::WithSecret);
    }

    // Windows QGpgME new style connect problem makes this necessary.
    connect(job,
            SIGNAL(result(GpgME::KeyListResult, std::vector<GpgME::Key>, QString, GpgME::Error)),
            this,
            SLOT(keyListDone(GpgME::KeyListResult, std::vector<GpgME::Key>, QString, GpgME::Error)));

    job->start(QStringList() << QLatin1String(key.primaryFingerprint()));
}

GpgME::Key CertificateDetailsWidget::key() const
{
    return d->key;
}

#include "moc_certificatedetailswidget.cpp"
