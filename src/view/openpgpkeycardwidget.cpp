/*  view/openpgpkeycardwidget.cpp

    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2021, 2022 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include "openpgpkeycardwidget.h"

#include "commands/detailscommand.h"

#include "smartcard/card.h"
#include "smartcard/keypairinfo.h"
#include "smartcard/openpgpcard.h"

#include <Libkleo/Compliance>
#include <Libkleo/Formatting>
#include <Libkleo/KeyCache>

#include <KLocalizedString>
#include <KMessageBox>

#include <QGridLayout>
#include <QLabel>
#include <QPushButton>

#include <gpgme++/key.h>

using namespace Kleo;
using namespace SmartCard;

namespace
{
struct KeyWidgets {
    std::string cardKeyRef;
    std::string keyFingerprint;
    KeyPairInfo keyInfo;
    QLabel *keyTitleLabel = nullptr;
    QLabel *keyInfoLabel = nullptr;
    QPushButton *showCertificateDetailsButton = nullptr;
    QPushButton *generateButton = nullptr;
    QPushButton *createCSRButton = nullptr;
};

KeyWidgets createKeyWidgets(const KeyPairInfo &keyInfo, QWidget *parent)
{
    KeyWidgets keyWidgets;
    keyWidgets.keyTitleLabel = new QLabel{OpenPGPCard::keyDisplayName(keyInfo.keyRef), parent};
    keyWidgets.keyInfoLabel = new QLabel{parent};
    keyWidgets.keyInfoLabel->setTextInteractionFlags(Qt::TextBrowserInteraction | Qt::TextSelectableByKeyboard);
    keyWidgets.showCertificateDetailsButton = new QPushButton{i18nc("@action:button", "Show Details"), parent};
    keyWidgets.showCertificateDetailsButton->setToolTip(i18nc("@action:tooltip", "Show detailed information about this key"));
    keyWidgets.showCertificateDetailsButton->setEnabled(false);
    keyWidgets.generateButton = new QPushButton{i18nc("@action:button", "Generate Key"), parent};
    keyWidgets.generateButton->setEnabled(false);
    if (keyInfo.canCertify() || keyInfo.canSign() || keyInfo.canAuthenticate()) {
        keyWidgets.createCSRButton = new QPushButton{i18nc("@action:button", "Create CSR"), parent};
        keyWidgets.createCSRButton->setToolTip(i18nc("@info:tooltip", "Create a certificate signing request for this key"));
        keyWidgets.createCSRButton->setEnabled(false);
    }

    return keyWidgets;
}
}

class OpenPGPKeyCardWidget::Private
{
public:
    explicit Private(OpenPGPKeyCardWidget *q);
    ~Private() = default;

    void setAllowedActions(Actions actions);
    void update(const Card *card = nullptr);

private:
    void updateCachedValues(const std::string &openPGPKeyRef, const std::string &cardKeyRef, const Card *card);
    void updateKeyWidgets(const std::string &openPGPKeyRef);

    void showCertificateDetails(const std::string &openPGPKeyRef);

private:
    OpenPGPKeyCardWidget *const q;
    Actions mAllowedActions = AllActions;
    std::map<std::string, KeyWidgets> mKeyWidgets;
};

OpenPGPKeyCardWidget::Private::Private(OpenPGPKeyCardWidget *q)
    : q{q}
{
    auto grid = new QGridLayout{q};
    grid->setContentsMargins(0, 0, 0, 0);
    for (const auto &keyInfo : OpenPGPCard::supportedKeys()) {
        const KeyWidgets keyWidgets = createKeyWidgets(keyInfo, q);

        const std::string keyRef = keyInfo.keyRef;
        connect(keyWidgets.showCertificateDetailsButton, &QPushButton::clicked, q, [this, keyRef]() {
            showCertificateDetails(keyRef);
        });
        connect(keyWidgets.generateButton, &QPushButton::clicked, q, [q, keyRef]() {
            Q_EMIT q->generateKeyRequested(keyRef);
        });
        if (keyWidgets.createCSRButton) {
            connect(keyWidgets.createCSRButton, &QPushButton::clicked, q, [q, keyRef]() {
                Q_EMIT q->createCSRRequested(keyRef);
            });
        }

        const int row = grid->rowCount();
        grid->addWidget(keyWidgets.keyTitleLabel, row, 0, Qt::AlignTop);
        grid->addWidget(keyWidgets.keyInfoLabel, row, 1, Qt::AlignTop);

        auto buttons = new QHBoxLayout;
        buttons->addWidget(keyWidgets.showCertificateDetailsButton);
        buttons->addWidget(keyWidgets.generateButton);
        if (keyWidgets.createCSRButton) {
            buttons->addWidget(keyWidgets.createCSRButton);
        }
        buttons->addStretch(1);
        grid->addLayout(buttons, row, 2, Qt::AlignTop);

        mKeyWidgets.insert({keyInfo.keyRef, keyWidgets});
    }
    grid->setColumnStretch(grid->columnCount(), 1);
}

void OpenPGPKeyCardWidget::Private::setAllowedActions(Actions actions)
{
    mAllowedActions = actions;
    update();
}

void OpenPGPKeyCardWidget::Private::update(const Card *card)
{
    if (card) {
        updateCachedValues(OpenPGPCard::pgpSigKeyRef(), card->signingKeyRef(), card);
        updateCachedValues(OpenPGPCard::pgpEncKeyRef(), card->encryptionKeyRef(), card);
        updateCachedValues(OpenPGPCard::pgpAuthKeyRef(), card->authenticationKeyRef(), card);
    }
    updateKeyWidgets(OpenPGPCard::pgpSigKeyRef());
    updateKeyWidgets(OpenPGPCard::pgpEncKeyRef());
    updateKeyWidgets(OpenPGPCard::pgpAuthKeyRef());
}

void OpenPGPKeyCardWidget::Private::updateCachedValues(const std::string &openPGPKeyRef, const std::string &cardKeyRef, const Card *card)
{
    KeyWidgets &widgets = mKeyWidgets.at(openPGPKeyRef);
    widgets.cardKeyRef = cardKeyRef;
    widgets.keyFingerprint = card->keyFingerprint(openPGPKeyRef);
    widgets.keyInfo = card->keyInfo(cardKeyRef);
}

void OpenPGPKeyCardWidget::Private::updateKeyWidgets(const std::string &openPGPKeyRef)
{
    const KeyWidgets &widgets = mKeyWidgets.at(openPGPKeyRef);

    const auto cardSupportsKey = !widgets.cardKeyRef.empty();
    widgets.keyTitleLabel->setVisible(cardSupportsKey);
    widgets.keyInfoLabel->setVisible(cardSupportsKey);
    widgets.showCertificateDetailsButton->setVisible(cardSupportsKey);
    widgets.generateButton->setVisible(cardSupportsKey && (mAllowedActions & Action::GenerateKey) && !DeVSCompliance::isActive());
    if (widgets.createCSRButton) {
        widgets.createCSRButton->setVisible(cardSupportsKey && (mAllowedActions & Action::CreateCSR));
    }
    if (!cardSupportsKey) {
        return;
    }

    widgets.showCertificateDetailsButton->setEnabled(false);

    if (widgets.keyFingerprint.empty()) {
        widgets.keyInfoLabel->setTextFormat(Qt::RichText);
        widgets.keyInfoLabel->setText(i18nc("@info", "<em>No key</em>"));
        widgets.generateButton->setText(i18nc("@action:button", "Generate Key"));
        widgets.generateButton->setToolTip(i18nc("@info:tooltip", "Generate a key for this card slot"));
        if (widgets.createCSRButton) {
            widgets.createCSRButton->setEnabled(false);
        }
    } else {
        QStringList lines;
        if (widgets.keyFingerprint.size() >= 16) {
            const std::string keyid = widgets.keyFingerprint.substr(widgets.keyFingerprint.size() - 16);
            const auto subkeys = KeyCache::instance()->findSubkeysByKeyID({keyid});
            if (subkeys.empty() || subkeys[0].isNull()) {
                widgets.keyInfoLabel->setTextFormat(Qt::RichText);
                lines.push_back(i18nc("@info", "<em>Public key not found locally</em>"));
                widgets.keyInfoLabel->setToolTip({});
            } else {
                // force interpretation of text as plain text to avoid problems with HTML in user IDs
                widgets.keyInfoLabel->setTextFormat(Qt::PlainText);
                QStringList toolTips;
                toolTips.reserve(subkeys.size());
                for (const auto &sub : subkeys) {
                    // Yep you can have one subkey associated with multiple primary keys.
                    const GpgME::Key key = sub.parent();
                    toolTips << Formatting::toolTip(key, Formatting::Validity | Formatting::ExpiryDates | Formatting::UserIDs | Formatting::Fingerprint);
                    const auto uids = key.userIDs();
                    for (const auto &uid : uids) {
                        lines.push_back(Formatting::prettyUserID(uid));
                    }
                }
                widgets.keyInfoLabel->setToolTip(toolTips.join(QLatin1String("<br/>")));
                widgets.showCertificateDetailsButton->setEnabled(true);
            }
        } else {
            widgets.keyInfoLabel->setTextFormat(Qt::RichText);
            lines.push_back(i18nc("@info", "<em>Invalid fingerprint</em>"));
        }

        const QString fingerprint = widgets.keyInfoLabel->textFormat() == Qt::RichText
            ? Formatting::prettyID(widgets.keyFingerprint.c_str()).replace(QLatin1Char(' '), QLatin1String("&nbsp;"))
            : Formatting::prettyID(widgets.keyFingerprint.c_str());
        lines.insert(0, fingerprint);
        const auto lineSeparator = widgets.keyInfoLabel->textFormat() == Qt::PlainText ? QLatin1String("\n") : QLatin1String("<br>");
        widgets.keyInfoLabel->setText(lines.join(lineSeparator));

        widgets.generateButton->setText(i18nc("@action:button", "Regenerate Key"));
        widgets.generateButton->setToolTip(i18nc("@info:tooltip", "Generate a new key for this card slot replacing the existing key"));
        if (widgets.createCSRButton) {
            widgets.createCSRButton->setEnabled(DeVSCompliance::algorithmIsCompliant(widgets.keyInfo.algorithm));
        }
    }

    widgets.generateButton->setEnabled(!widgets.generateButton->isHidden());
}

void OpenPGPKeyCardWidget::Private::showCertificateDetails(const std::string &openPGPKeyRef)
{
    const KeyWidgets &widgets = mKeyWidgets.at(openPGPKeyRef);

    if (widgets.keyFingerprint.size() >= 16) {
        const std::string keyid = widgets.keyFingerprint.substr(widgets.keyFingerprint.size() - 16);
        const auto subkeys = KeyCache::instance()->findSubkeysByKeyID({keyid});
        if (!subkeys.empty() && !subkeys[0].isNull()) {
            auto cmd = new Commands::DetailsCommand(subkeys[0].parent());
            cmd->setParentWidget(q);
            cmd->start();
            return;
        }
    }
    KMessageBox::error(q, i18nc("@info", "Sorry, I cannot find the key with fingerprint %1.", Formatting::prettyID(widgets.keyFingerprint.c_str())));
}

OpenPGPKeyCardWidget::OpenPGPKeyCardWidget(QWidget *parent)
    : QWidget{parent}
    , d{std::make_unique<Private>(this)}
{
    connect(KeyCache::instance().get(), &KeyCache::keysMayHaveChanged, this, [this]() {
        d->update();
    });
}

OpenPGPKeyCardWidget::~OpenPGPKeyCardWidget() = default;

void OpenPGPKeyCardWidget::setAllowedActions(Actions actions)
{
    d->setAllowedActions(actions);
}

void OpenPGPKeyCardWidget::update(const Card *card)
{
    d->update(card);
}
