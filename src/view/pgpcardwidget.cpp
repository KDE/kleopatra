/*  view/pgpcardwiget.cpp

    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2017 Bundesamt für Sicherheit in der Informationstechnik
    SPDX-FileContributor: Intevation GmbH
    SPDX-FileCopyrightText: 2020, 2022 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include <config-kleopatra.h>

#include "pgpcardwidget.h"

#include "kleopatra_debug.h"

#include <commands/generateopenpgpcardkeysandcertificatecommand.h>

#include "smartcard/openpgpcard.h"
#include "smartcard/readerstatus.h"

#include <view/cardkeysview.h>

#include <utils/qt-cxx20-compat.h>

#include <QGridLayout>
#include <QHBoxLayout>
#include <QInputDialog>
#include <QLabel>
#include <QPushButton>
#include <QVBoxLayout>

#include <KLocalizedString>
#include <KMessageBox>

#include <Libkleo/Formatting>

using namespace Kleo;
using namespace Kleo::Commands;
using namespace Kleo::SmartCard;

PGPCardWidget::PGPCardWidget(QWidget *parent)
    : SmartCardWidget(parent)
{
    {
        mInfoGridLayout->setColumnStretch(mInfoGridLayout->columnCount() - 1, 0); // undo stretch set by base widget
        int row = mInfoGridLayout->rowCount();

        // Cardholder Row
        mInfoGridLayout->addWidget(new QLabel(i18nc("The owner of a smartcard. GnuPG refers to this as cardholder.", "Cardholder:")), row, 0);
        mCardHolderLabel = new QLabel{this};
        mCardHolderLabel->setTextInteractionFlags(Qt::TextBrowserInteraction);
        mInfoGridLayout->addWidget(mCardHolderLabel, row, 1);
        {
            auto button = new QPushButton{this};
            button->setIcon(QIcon::fromTheme(QStringLiteral("cell_edit")));
            button->setAccessibleName(i18nc("@action:button", "Edit"));
            button->setToolTip(i18n("Change"));
            mInfoGridLayout->addWidget(button, row, 2);
            connect(button, &QPushButton::clicked, this, &PGPCardWidget::changeNameRequested);
        }
        row++;

        // URL Row
        mInfoGridLayout->addWidget(new QLabel(i18nc("The URL under which a public key that "
                                                    "corresponds to a smartcard can be downloaded",
                                                    "Pubkey URL:")),
                                   row,
                                   0);
        mUrlLabel = new QLabel{this};
        mUrlLabel->setTextInteractionFlags(Qt::TextBrowserInteraction);
        mInfoGridLayout->addWidget(mUrlLabel, row, 1);
        {
            auto button = new QPushButton{this};
            button->setIcon(QIcon::fromTheme(QStringLiteral("cell_edit")));
            button->setAccessibleName(i18nc("@action:button", "Edit"));
            button->setToolTip(i18n("Change"));
            mInfoGridLayout->addWidget(button, row, 2);
            connect(button, &QPushButton::clicked, this, &PGPCardWidget::changeUrlRequested);
        }

        mInfoGridLayout->setColumnStretch(mInfoGridLayout->columnCount(), 1);
    }

    mCardKeysView = new CardKeysView{this};
    mContentLayout->addWidget(mCardKeysView, 1);

    auto actionLayout = new QHBoxLayout;

    {
        auto generateButton = new QPushButton(i18n("Generate New Keys"), this);
        generateButton->setToolTip(xi18nc("@info:tooltip",
                                          "<para>Generate three new keys on the smart card and create a new OpenPGP "
                                          "certificate with those keys. Optionally, the encryption key is generated "
                                          "off-card and a backup is created so that you can still access data encrypted "
                                          "with this key in case the card is lost or damaged.</para>"
                                          "<para><emphasis strong='true'>"
                                          "Existing keys on the smart card will be overwritten."
                                          "</emphasis></para>"));
        actionLayout->addWidget(generateButton);
        connect(generateButton, &QPushButton::clicked, this, &PGPCardWidget::genkeyRequested);
    }
    {
        auto pinButton = new QPushButton(i18n("Change PIN"), this);
        pinButton->setToolTip(i18nc("@info:tooltip",
                                    "Change the PIN required for using the keys on the smart card. "
                                    "The PIN must contain at least six characters."));
        actionLayout->addWidget(pinButton);
        connect(pinButton, &QPushButton::clicked, this, [this]() {
            doChangePin(OpenPGPCard::pinKeyRef());
        });
    }
    {
        auto unblockButton = new QPushButton(i18n("Unblock Card"), this);
        unblockButton->setToolTip(i18nc("@info:tooltip", "Unblock the smart card with the PUK."));
        actionLayout->addWidget(unblockButton);
        connect(unblockButton, &QPushButton::clicked, this, [this]() {
            doChangePin(OpenPGPCard::resetCodeKeyRef());
        });
    }
    {
        auto pukButton = new QPushButton(i18n("Change Admin PIN"), this);
        pukButton->setToolTip(i18nc("@info:tooltip", "Change the PIN required for administrative operations."));
        actionLayout->addWidget(pukButton);
        connect(pukButton, &QPushButton::clicked, this, [this]() {
            doChangePin(OpenPGPCard::adminPinKeyRef());
        });
    }
    {
        auto resetCodeButton = new QPushButton(i18n("Change PUK"), this);
        resetCodeButton->setToolTip(i18nc("@info:tooltip",
                                          "Set or change the PUK required to unblock the smart card. "
                                          "The PUK must contain at least eight characters."));
        actionLayout->addWidget(resetCodeButton);
        connect(resetCodeButton, &QPushButton::clicked, this, [this]() {
            doChangePin(OpenPGPCard::resetCodeKeyRef(), ChangePinCommand::ResetMode);
        });
    }

    actionLayout->addStretch(-1);
    mContentLayout->addLayout(actionLayout);
}

void PGPCardWidget::setCard(const OpenPGPCard *card)
{
    SmartCardWidget::setCard(card);

    mIs21 = card->appVersion() >= 0x0201;

    const auto holder = card->cardHolder();
    const auto url = QString::fromStdString(card->pubkeyUrl());
    mCardHolderLabel->setText(holder.isEmpty() ? i18n("not set") : holder);
    mUrl = url;
    mUrlLabel->setText(url.isEmpty() ? i18n("not set") : QStringLiteral("<a href=\"%1\">%1</a>").arg(url.toHtmlEscaped()));
    mUrlLabel->setOpenExternalLinks(true);
}

void PGPCardWidget::doChangePin(const std::string &keyRef, ChangePinCommand::ChangePinMode mode)
{
    auto cmd = new ChangePinCommand(serialNumber(), OpenPGPCard::AppName, this);
    this->setEnabled(false);
    connect(cmd, &ChangePinCommand::finished, this, [this]() {
        this->setEnabled(true);
    });
    cmd->setKeyRef(keyRef);
    cmd->setMode(mode);
    cmd->start();
}

void PGPCardWidget::genkeyRequested()
{
    auto cmd = new GenerateOpenPGPCardKeysAndCertificateCommand(serialNumber(), this);
    this->setEnabled(false);
    connect(cmd, &Command::finished, this, [this]() {
        this->setEnabled(true);
    });
    cmd->start();
}

void PGPCardWidget::changeNameRequested()
{
    QString text = mCardHolderLabel->text();
    while (true) {
        bool ok = false;
        text = QInputDialog::getText(this, i18n("Change cardholder"), i18n("New name:"), QLineEdit::Normal, text, &ok, Qt::WindowFlags(), Qt::ImhLatinOnly);
        if (!ok) {
            return;
        }
        // Some additional restrictions imposed by gnupg
        if (text.contains(QLatin1Char('<'))) {
            KMessageBox::error(this, i18nc("@info", "The \"<\" character may not be used."));
            continue;
        }
        if (text.contains(QLatin1String("  "))) {
            KMessageBox::error(this, i18nc("@info", "Double spaces are not allowed"));
            continue;
        }
        if (text.size() > 38) {
            KMessageBox::error(this, i18nc("@info", "The size of the name may not exceed 38 characters."));
        }
        break;
    }
    auto parts = text.split(QLatin1Char(' '));
    const auto lastName = parts.takeLast();
    const QString formatted = lastName + QStringLiteral("<<") + parts.join(QLatin1Char('<'));

    const auto pgpCard = ReaderStatus::instance()->getCard<OpenPGPCard>(serialNumber());
    if (!pgpCard) {
        KMessageBox::error(this, i18n("Failed to find the OpenPGP card with the serial number: %1", QString::fromStdString(serialNumber())));
        return;
    }

    const QByteArray command = QByteArrayLiteral("SCD SETATTR DISP-NAME ") + formatted.toUtf8();
    ReaderStatus::mutableInstance()->startSimpleTransaction(pgpCard, command, this, [this](const GpgME::Error &err) {
        changeNameResult(err);
    });
}

void PGPCardWidget::changeNameResult(const GpgME::Error &err)
{
    if (err) {
        KMessageBox::error(this, i18nc("@info", "Name change failed: %1", Formatting::errorAsString(err)));
        return;
    }
    if (!err.isCanceled()) {
        KMessageBox::information(this, i18nc("@info", "Name successfully changed."), i18nc("@title", "Success"));
        ReaderStatus::mutableInstance()->updateStatus();
    }
}

void PGPCardWidget::changeUrlRequested()
{
    QString text = mUrl;
    while (true) {
        bool ok = false;
        text = QInputDialog::getText(this,
                                     i18n("Change the URL where the pubkey can be found"),
                                     i18n("New pubkey URL:"),
                                     QLineEdit::Normal,
                                     text,
                                     &ok,
                                     Qt::WindowFlags(),
                                     Qt::ImhLatinOnly);
        if (!ok) {
            return;
        }
        // Some additional restrictions imposed by gnupg
        if (text.size() > 254) {
            KMessageBox::error(this, i18nc("@info", "The size of the URL may not exceed 254 characters."));
        }
        break;
    }

    const auto pgpCard = ReaderStatus::instance()->getCard<OpenPGPCard>(serialNumber());
    if (!pgpCard) {
        KMessageBox::error(this, i18n("Failed to find the OpenPGP card with the serial number: %1", QString::fromStdString(serialNumber())));
        return;
    }

    const QByteArray command = QByteArrayLiteral("SCD SETATTR PUBKEY-URL ") + text.toUtf8();
    ReaderStatus::mutableInstance()->startSimpleTransaction(pgpCard, command, this, [this](const GpgME::Error &err) {
        changeUrlResult(err);
    });
}

void PGPCardWidget::changeUrlResult(const GpgME::Error &err)
{
    if (err) {
        KMessageBox::error(this, i18nc("@info", "URL change failed: %1", Formatting::errorAsString(err)));
        return;
    }
    if (!err.isCanceled()) {
        KMessageBox::information(this, i18nc("@info", "URL successfully changed."), i18nc("@title", "Success"));
        ReaderStatus::mutableInstance()->updateStatus();
    }
}
