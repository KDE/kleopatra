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

#include "openpgpkeycardwidget.h"

#include "kleopatra_debug.h"

#include "commands/createcsrforcardkeycommand.h"
#include "commands/openpgpgeneratecardkeycommand.h"

#include "smartcard/algorithminfo.h"
#include "smartcard/openpgpcard.h"
#include "smartcard/readerstatus.h"
#include "smartcard/utils.h"

#include "dialogs/gencardkeydialog.h"

#include <utils/qt-cxx20-compat.h>

#include <Libkleo/Compliance>
#include <Libkleo/GnuPG>

#include <QFileDialog>
#include <QFileInfo>
#include <QGridLayout>
#include <QHBoxLayout>
#include <QInputDialog>
#include <QLabel>
#include <QProgressDialog>
#include <QPushButton>
#include <QScrollArea>
#include <QThread>
#include <QVBoxLayout>

#include <KLocalizedString>
#include <KMessageBox>
#include <KSeparator>

#include <Libkleo/Formatting>
#include <Libkleo/KeyCache>

#include <gpgme++/context.h>
#include <gpgme++/data.h>

#include <QGpgME/DataProvider>

#include <gpgme++/gpggencardkeyinteractor.h>

using namespace Kleo;
using namespace Kleo::Commands;
using namespace Kleo::SmartCard;

namespace
{
class GenKeyThread : public QThread
{
    Q_OBJECT

public:
    explicit GenKeyThread(const GenCardKeyDialog::KeyParams &params, const std::string &serial)
        : mSerial(serial)
        , mParams(params)
    {
    }

    GpgME::Error error()
    {
        return mErr;
    }

    std::string bkpFile()
    {
        return mBkpFile;
    }

protected:
    void run() override
    {
        // the index of the curves in this list has to match the enum values
        // minus 1 of GpgGenCardKeyInteractor::Curve
        static const std::vector<std::string> curves = {
            "curve25519",
            "curve448",
            "nistp256",
            "nistp384",
            "nistp521",
            "brainpoolP256r1",
            "brainpoolP384r1",
            "brainpoolP512r1",
            "secp256k1", // keep it, even if we don't support it in Kleopatra
        };

        auto ei = std::make_unique<GpgME::GpgGenCardKeyInteractor>(mSerial);
        if (mParams.algorithm.starts_with("rsa")) {
            ei->setAlgo(GpgME::GpgGenCardKeyInteractor::RSA);
            ei->setKeySize(QByteArray::fromStdString(mParams.algorithm.substr(3)).toInt());
        } else {
            ei->setAlgo(GpgME::GpgGenCardKeyInteractor::ECC);
            const auto curveIt = std::find(curves.cbegin(), curves.cend(), mParams.algorithm);
            if (curveIt != curves.end()) {
                ei->setCurve(static_cast<GpgME::GpgGenCardKeyInteractor::Curve>(curveIt - curves.cbegin() + 1));
            } else {
                qCWarning(KLEOPATRA_LOG) << this << __func__ << "Invalid curve name:" << mParams.algorithm;
                mErr = GpgME::Error::fromCode(GPG_ERR_INV_VALUE);
                return;
            }
        }
        ei->setNameUtf8(mParams.name.toStdString());
        ei->setEmailUtf8(mParams.email.toStdString());
        ei->setDoBackup(mParams.backup);

        const auto ctx = std::shared_ptr<GpgME::Context>(GpgME::Context::createForProtocol(GpgME::OpenPGP));
        ctx->setFlag("extended-edit", "1"); // we want to be able to select all curves
        QGpgME::QByteArrayDataProvider dp;
        GpgME::Data data(&dp);

        mErr = ctx->cardEdit(GpgME::Key(), std::move(ei), data);
        mBkpFile = static_cast<GpgME::GpgGenCardKeyInteractor *>(ctx->lastCardEditInteractor())->backupFileName();
    }

private:
    GpgME::Error mErr;
    std::string mSerial;
    GenCardKeyDialog::KeyParams mParams;

    std::string mBkpFile;
};

} // Namespace

PGPCardWidget::PGPCardWidget(QWidget *parent)
    : SmartCardWidget(parent)
{
    // Set up the scroll area
    auto myLayout = new QVBoxLayout(this);
    myLayout->setContentsMargins(0, 0, 0, 0);

    auto area = new QScrollArea;
    area->setFocusPolicy(Qt::NoFocus);
    area->setFrameShape(QFrame::NoFrame);
    area->setWidgetResizable(true);
    myLayout->addWidget(area);

    auto areaWidget = new QWidget;
    area->setWidget(areaWidget);

    auto areaVLay = new QVBoxLayout(areaWidget);

    auto cardInfoGrid = new QGridLayout;
    {
        int row = 0;

        // Version and Serialnumber
        mVersionLabel = new QLabel{this};
        mVersionLabel->setTextInteractionFlags(Qt::TextBrowserInteraction);
        cardInfoGrid->addWidget(mVersionLabel, row, 0, 1, 2);
        row++;

        cardInfoGrid->addWidget(new QLabel(i18n("Serial number:")), row, 0);
        mSerialNumberLabel = new QLabel{this};
        mSerialNumberLabel->setTextInteractionFlags(Qt::TextBrowserInteraction);
        cardInfoGrid->addWidget(mSerialNumberLabel, row, 1);
        row++;

        // Cardholder Row
        cardInfoGrid->addWidget(new QLabel(i18nc("The owner of a smartcard. GnuPG refers to this as cardholder.", "Cardholder:")), row, 0);
        mCardHolderLabel = new QLabel{this};
        mCardHolderLabel->setTextInteractionFlags(Qt::TextBrowserInteraction);
        cardInfoGrid->addWidget(mCardHolderLabel, row, 1);
        {
            auto button = new QPushButton{this};
            button->setIcon(QIcon::fromTheme(QStringLiteral("cell_edit")));
            button->setAccessibleName(i18nc("@action:button", "Edit"));
            button->setToolTip(i18n("Change"));
            cardInfoGrid->addWidget(button, row, 2);
            connect(button, &QPushButton::clicked, this, &PGPCardWidget::changeNameRequested);
        }
        row++;

        // URL Row
        cardInfoGrid->addWidget(new QLabel(i18nc("The URL under which a public key that "
                                                 "corresponds to a smartcard can be downloaded",
                                                 "Pubkey URL:")),
                                row,
                                0);
        mUrlLabel = new QLabel{this};
        mUrlLabel->setTextInteractionFlags(Qt::TextBrowserInteraction);
        cardInfoGrid->addWidget(mUrlLabel, row, 1);
        {
            auto button = new QPushButton{this};
            button->setIcon(QIcon::fromTheme(QStringLiteral("cell_edit")));
            button->setAccessibleName(i18nc("@action:button", "Edit"));
            button->setToolTip(i18n("Change"));
            cardInfoGrid->addWidget(button, row, 2);
            connect(button, &QPushButton::clicked, this, &PGPCardWidget::changeUrlRequested);
        }

        cardInfoGrid->setColumnStretch(cardInfoGrid->columnCount(), 1);
    }
    areaVLay->addLayout(cardInfoGrid);

    areaVLay->addWidget(new KSeparator(Qt::Horizontal));

    // The keys
    areaVLay->addWidget(new QLabel(QStringLiteral("<b>%1</b>").arg(i18n("Keys:"))));

    mKeysWidget = new OpenPGPKeyCardWidget{this};
    areaVLay->addWidget(mKeysWidget);
    connect(mKeysWidget, &OpenPGPKeyCardWidget::createCSRRequested, this, &PGPCardWidget::createCSR);
    connect(mKeysWidget, &OpenPGPKeyCardWidget::generateKeyRequested, this, &PGPCardWidget::generateKey);

    areaVLay->addWidget(new KSeparator(Qt::Horizontal));

    areaVLay->addWidget(new QLabel(QStringLiteral("<b>%1</b>").arg(i18n("Actions:"))));

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
    areaVLay->addLayout(actionLayout);

    areaVLay->addStretch(1);
}

void PGPCardWidget::setCard(const OpenPGPCard *card)
{
    const QString version = card->displayAppVersion();

    mIs21 = card->appVersion() >= 0x0201;
    const QString manufacturer = QString::fromStdString(card->manufacturer());
    const bool manufacturerIsUnknown = manufacturer.isEmpty() || manufacturer == QLatin1String("unknown");
    mVersionLabel->setText(
        manufacturerIsUnknown
            ? i18nc("Placeholder is a version number", "Unknown OpenPGP v%1 card", version)
            : i18nc("First placeholder is manufacturer, second placeholder is a version number", "%1 OpenPGP v%2 card", manufacturer, version));
    mSerialNumberLabel->setText(card->displaySerialNumber());
    mSerialNumber = card->serialNumber();

    const auto holder = card->cardHolder();
    const auto url = QString::fromStdString(card->pubkeyUrl());
    mCardHolderLabel->setText(holder.isEmpty() ? i18n("not set") : holder);
    mUrl = url;
    mUrlLabel->setText(url.isEmpty() ? i18n("not set") : QStringLiteral("<a href=\"%1\">%1</a>").arg(url.toHtmlEscaped()));
    mUrlLabel->setOpenExternalLinks(true);

    mKeysWidget->update(card);

    mCardIsEmpty = card->keyFingerprint(OpenPGPCard::pgpSigKeyRef()).empty() && card->keyFingerprint(OpenPGPCard::pgpEncKeyRef()).empty()
        && card->keyFingerprint(OpenPGPCard::pgpAuthKeyRef()).empty();
}

void PGPCardWidget::doChangePin(const std::string &keyRef, ChangePinCommand::ChangePinMode mode)
{
    auto cmd = new ChangePinCommand(mSerialNumber, OpenPGPCard::AppName, this);
    this->setEnabled(false);
    connect(cmd, &ChangePinCommand::finished, this, [this]() {
        this->setEnabled(true);
    });
    cmd->setKeyRef(keyRef);
    cmd->setMode(mode);
    cmd->start();
}

void PGPCardWidget::doGenKey(GenCardKeyDialog *dlg)
{
    const GpgME::Error err = ReaderStatus::switchCardAndApp(mSerialNumber, OpenPGPCard::AppName);
    if (err) {
        return;
    }

    const auto params = dlg->getKeyParams();

    auto progress = new QProgressDialog(this, Qt::CustomizeWindowHint | Qt::WindowTitleHint | Qt::Dialog);
    progress->setAutoClose(true);
    progress->setMinimumDuration(0);
    progress->setMaximum(0);
    progress->setMinimum(0);
    progress->setModal(true);
    progress->setCancelButton(nullptr);
    progress->setWindowTitle(i18nc("@title:window", "Generating Keys"));
    progress->setLabel(new QLabel(i18n("This may take several minutes...")));
    auto workerThread = new GenKeyThread(params, mSerialNumber);
    connect(workerThread, &QThread::finished, this, [this, workerThread, progress] {
        progress->accept();
        progress->deleteLater();
        genKeyDone(workerThread->error(), workerThread->bkpFile());
        delete workerThread;
    });
    workerThread->start();
    progress->exec();
}

void PGPCardWidget::genKeyDone(const GpgME::Error &err, const std::string &backup)
{
    if (err) {
        KMessageBox::error(this, i18nc("@info", "Failed to generate new key: %1", Formatting::errorAsString(err)));
        return;
    }
    if (err.isCanceled()) {
        return;
    }
    if (!backup.empty()) {
        const auto bkpFile = QString::fromStdString(backup);
        QFileInfo fi(bkpFile);
        const auto target =
            QFileDialog::getSaveFileName(this, i18n("Save backup of encryption key"), fi.fileName(), QStringLiteral("%1 (*.gpg)").arg(i18n("Backup Key")));
        if (!target.isEmpty() && !QFile::copy(bkpFile, target)) {
            KMessageBox::error(this, i18nc("@info", "Failed to move backup. The backup key is still stored under: %1", bkpFile));
        } else if (!target.isEmpty()) {
            QFile::remove(bkpFile);
        }
    }

    KMessageBox::information(this, i18nc("@info", "Successfully generated a new key for this card."), i18nc("@title", "Success"));
    ReaderStatus::mutableInstance()->updateStatus();
}

void PGPCardWidget::genkeyRequested()
{
    const auto pgpCard = ReaderStatus::instance()->getCard<OpenPGPCard>(mSerialNumber);
    if (!pgpCard) {
        KMessageBox::error(this, i18n("Failed to find the OpenPGP card with the serial number: %1", QString::fromStdString(mSerialNumber)));
        return;
    }

    if (!mCardIsEmpty) {
        auto ret = KMessageBox::warningContinueCancel(this,
                                                      i18n("The existing keys on this card will be <b>deleted</b> "
                                                           "and replaced by new keys.")
                                                          + QStringLiteral("<br/><br/>")
                                                          + i18n("It will no longer be possible to decrypt past communication "
                                                                 "encrypted for the existing key."),
                                                      i18n("Secret Key Deletion"),
                                                      KStandardGuiItem::guiItem(KStandardGuiItem::Delete),
                                                      KStandardGuiItem::cancel(),
                                                      QString(),
                                                      KMessageBox::Notify | KMessageBox::Dangerous);

        if (ret != KMessageBox::Continue) {
            return;
        }
    }

    auto dlg = new GenCardKeyDialog(GenCardKeyDialog::AllKeyAttributes, this);
    const auto allowedAlgos = getAllowedAlgorithms(pgpCard->supportedAlgorithms());
    if (allowedAlgos.empty()) {
        KMessageBox::error(this, i18nc("@info", "You cannot generate keys on this smart card because it doesn't support any of the compliant algorithms."));
        return;
    }
    dlg->setSupportedAlgorithms(allowedAlgos, getPreferredAlgorithm(allowedAlgos));
    connect(dlg, &QDialog::accepted, this, [this, dlg]() {
        doGenKey(dlg);
        dlg->deleteLater();
    });
    dlg->setModal(true);
    dlg->show();
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

    const auto pgpCard = ReaderStatus::instance()->getCard<OpenPGPCard>(mSerialNumber);
    if (!pgpCard) {
        KMessageBox::error(this, i18n("Failed to find the OpenPGP card with the serial number: %1", QString::fromStdString(mSerialNumber)));
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

    const auto pgpCard = ReaderStatus::instance()->getCard<OpenPGPCard>(mSerialNumber);
    if (!pgpCard) {
        KMessageBox::error(this, i18n("Failed to find the OpenPGP card with the serial number: %1", QString::fromStdString(mSerialNumber)));
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

void PGPCardWidget::createCSR(const std::string &keyref)
{
    auto cmd = new CreateCSRForCardKeyCommand(keyref, mSerialNumber, OpenPGPCard::AppName, this);
    this->setEnabled(false);
    connect(cmd, &CreateCSRForCardKeyCommand::finished, this, [this]() {
        this->setEnabled(true);
    });
    cmd->start();
}

void PGPCardWidget::generateKey(const std::string &keyref)
{
    auto cmd = new OpenPGPGenerateCardKeyCommand(keyref, mSerialNumber, this);
    this->setEnabled(false);
    connect(cmd, &OpenPGPGenerateCardKeyCommand::finished, this, [this]() {
        this->setEnabled(true);
    });
    cmd->start();
}

#include "pgpcardwidget.moc"
