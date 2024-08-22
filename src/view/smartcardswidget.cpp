/*  view/smartcardswidget.cpp

    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2017 Bundesamt für Sicherheit in der Informationstechnik
    SPDX-FileContributor: Intevation GmbH
    SPDX-FileCopyrightText: 2020 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include "smartcardswidget.h"

#include "netkeywidget.h"
#include "p15cardwidget.h"
#include "pgpcardwidget.h"
#include "pivcardwidget.h"
#include "smartcardactions.h"
#include "smartcardwidget.h"

#include <commands/certificatetopivcardcommand.h>
#include <commands/changepincommand.h>
#include <commands/createcsrforcardkeycommand.h>
#include <commands/createopenpgpkeyfromcardkeyscommand.h>
#include <commands/detailscommand.h>
#include <commands/generateopenpgpcardkeysandcertificatecommand.h>
#include <commands/importcertificatefrompivcardcommand.h>
#include <commands/keytocardcommand.h>
#include <commands/openpgpgeneratecardkeycommand.h>
#include <commands/pivgeneratecardkeycommand.h>
#include <commands/setpivcardapplicationadministrationkeycommand.h>

#include "smartcard/netkeycard.h"
#include "smartcard/openpgpcard.h"
#include "smartcard/p15card.h"
#include "smartcard/pivcard.h"
#include "smartcard/readerstatus.h"
#include "smartcard/utils.h"

#include "kleopatra_debug.h"

#include <Libkleo/Formatting>

#include <KActionCollection>
#include <KLocalizedString>
#include <KMessageBox>

#include <QHBoxLayout>
#include <QInputDialog>
#include <QLabel>
#include <QLineEdit>
#include <QPointer>
#include <QStackedWidget>
#include <QTabWidget>
#include <QToolButton>
#include <QVBoxLayout>

#include <gpgme++/key.h>

using namespace GpgME;
using namespace Kleo;
using namespace Kleo::Commands;
using namespace Kleo::SmartCard;
using namespace Qt::Literals::StringLiterals;

namespace
{
class PlaceHolderWidget : public QWidget
{
    Q_OBJECT
public:
    explicit PlaceHolderWidget(QWidget *parent = nullptr)
        : QWidget{parent}
    {
        auto lay = new QVBoxLayout;
        lay->addStretch(-1);

        const QStringList supported{
            i18nc("OpenPGP refers to a smartcard protocol", "OpenPGP v2.0 or later"),
            i18nc("Gnuk is a cryptographic token for GnuPG", "Gnuk"),
            i18nc("NetKey refers to a smartcard protocol", "NetKey v3 or later"),
            i18nc("PIV refers to a smartcard protocol", "PIV (requires GnuPG 2.3 or later)"),
            i18nc("CardOS is a smartcard operating system", "CardOS 5 (various apps)"),
        };
        lay->addWidget(new QLabel(QStringLiteral("\t\t<h3>") + i18n("Please insert a compatible smartcard.") + QStringLiteral("</h3>"), this));
        lay->addSpacing(10);
        lay->addWidget(new QLabel(QStringLiteral("\t\t") + i18n("Kleopatra currently supports the following card types:") + QStringLiteral("<ul><li>")
                                      + supported.join(QLatin1StringView("</li><li>")) + QStringLiteral("</li></ul>"),
                                  this));
        lay->addSpacing(10);
        {
            auto hbox = new QHBoxLayout;
            hbox->addStretch(1);
            mReloadButton = new QToolButton{this};
            mReloadButton->setToolButtonStyle(Qt::ToolButtonTextBesideIcon);
            mReloadButton->setDefaultAction(SmartCardActions::instance()->action(u"reload"_s));
            hbox->addWidget(mReloadButton);
            hbox->addStretch(1);
            lay->addLayout(hbox);
        }
        lay->addStretch(-1);

        auto hLay = new QHBoxLayout(this);
        hLay->addStretch(-1);
        hLay->addLayout(lay);
        hLay->addStretch(-1);
        lay->addStretch(-1);

        connect(ReaderStatus::instance(), &ReaderStatus::currentActionChanged, this, &PlaceHolderWidget::updateReloadButton);
        updateReloadButton();
    }

    void updateReloadButton()
    {
        mReloadButton->setEnabled(ReaderStatus::instance()->currentAction() != ReaderStatus::UpdateCards);
    }

private:
    QToolButton *mReloadButton = nullptr;
};
} // namespace

class SmartCardsWidget::Private
{
    friend class ::Kleo::SmartCardsWidget;

public:
    Private(SmartCardsWidget *qq);

    const SmartCardWidget *currentCardWidget() const;
    AppType currentCardType() const;
    std::string currentSerialNumber() const;
    std::string currentCardSlot() const;
    GpgME::Key currentCertificate() const;

    void cardAddedOrChanged(const std::string &serialNumber, const std::string &appName);
    void cardRemoved(const std::string &serialNumber, const std::string &appName);

    void enableCurrentWidget();
    void disableCurrentWidget();
    void startCommand(Command *cmd);

    // card actions
    void generateCardKeysAndOpenPGPCertificate();
    void createOpenPGPCertificate();
    void changePin(const std::string &keyRef, ChangePinCommand::ChangePinMode mode = ChangePinCommand::NormalMode);
    void unblockOpenPGPCard();
    void changeCardholder();
    void changePublicKeyUrl();
    void setPIVAdminKey();

    // card slot actions
    void showCertificateDetails();
    void generateKey();
    void createCSR();
    void writeCertificateToCard();
    void readCertificateFromCard();
    void writeKeyToCard();

private:
    template<typename C, typename W>
    void cardAddedOrChanged(const std::string &serialNumber);

private:
    SmartCardsWidget *const q;
    QMap<std::pair<std::string, std::string>, QPointer<SmartCardWidget>> mCardWidgets;
    PlaceHolderWidget *mPlaceHolderWidget;
    QStackedWidget *mStack;
    QTabWidget *mTabWidget;
    QToolButton *mReloadButton;
};

SmartCardsWidget::Private::Private(SmartCardsWidget *qq)
    : q{qq}
{
    auto vLay = new QVBoxLayout(q);

    mStack = new QStackedWidget{q};
    vLay->addWidget(mStack);

    mPlaceHolderWidget = new PlaceHolderWidget{q};
    mStack->addWidget(mPlaceHolderWidget);

    mTabWidget = new QTabWidget{q};

    // create "Reload" button after tab widget to ensure correct tab order
    mReloadButton = new QToolButton{q};
    mTabWidget->setCornerWidget(mReloadButton, Qt::TopRightCorner);

    mStack->addWidget(mTabWidget);

    mStack->setCurrentWidget(mPlaceHolderWidget);

    connect(ReaderStatus::instance(), &ReaderStatus::cardAdded, q, [this](const std::string &serialNumber, const std::string &appName) {
        cardAddedOrChanged(serialNumber, appName);
    });
    connect(ReaderStatus::instance(), &ReaderStatus::cardChanged, q, [this](const std::string &serialNumber, const std::string &appName) {
        cardAddedOrChanged(serialNumber, appName);
    });
    connect(ReaderStatus::instance(), &ReaderStatus::cardRemoved, q, [this](const std::string &serialNumber, const std::string &appName) {
        cardRemoved(serialNumber, appName);
    });

    const auto actions = SmartCardActions::instance();
    actions->connectAction(u"reload"_s, q, &SmartCardsWidget::reload);
    mReloadButton->setDefaultAction(actions->action(u"reload"_s));

    // connect card actions
    actions->connectAction(u"card_all_create_openpgp_certificate"_s, q, [this]() {
        createOpenPGPCertificate();
    });
    actions->connectAction(u"card_netkey_set_nks_pin"_s, q, [this]() {
        changePin(NetKeyCard::nksPinKeyRef());
    });
    actions->connectAction(u"card_netkey_set_sigg_pin"_s, q, [this]() {
        changePin(NetKeyCard::sigGPinKeyRef());
    });
    actions->connectAction(u"card_pgp_generate_keys_and_certificate"_s, q, [this]() {
        generateCardKeysAndOpenPGPCertificate();
    });
    actions->connectAction(u"card_pgp_change_pin"_s, q, [this]() {
        changePin(OpenPGPCard::pinKeyRef());
    });
    actions->connectAction(u"card_pgp_unblock_card"_s, q, [this]() {
        unblockOpenPGPCard();
    });
    actions->connectAction(u"card_pgp_change_admin_pin"_s, q, [this]() {
        changePin(OpenPGPCard::adminPinKeyRef());
    });
    actions->connectAction(u"card_pgp_change_puk"_s, q, [this]() {
        changePin(OpenPGPCard::resetCodeKeyRef(), ChangePinCommand::ResetMode);
    });
    actions->connectAction(u"card_pgp_change_cardholder"_s, q, [this]() {
        changeCardholder();
    });
    actions->connectAction(u"card_pgp_change_publickeyurl"_s, q, [this]() {
        changePublicKeyUrl();
    });
    actions->connectAction(u"card_piv_change_pin"_s, q, [this]() {
        changePin(PIVCard::pinKeyRef());
    });
    actions->connectAction(u"card_piv_change_puk"_s, q, [this]() {
        changePin(PIVCard::pukKeyRef());
    });
    actions->connectAction(u"card_piv_change_admin_key"_s, q, [this]() {
        setPIVAdminKey();
    });

    // connect card slot actions
    actions->connectAction(u"card_slot_show_certificate_details"_s, q, [this]() {
        showCertificateDetails();
    });
    actions->connectAction(u"card_slot_generate_key"_s, q, [this]() {
        generateKey();
    });
    actions->connectAction(u"card_slot_write_key"_s, q, [this]() {
        writeKeyToCard();
    });
    actions->connectAction(u"card_slot_write_certificate"_s, q, [this]() {
        writeCertificateToCard();
    });
    actions->connectAction(u"card_slot_read_certificate"_s, q, [this]() {
        readCertificateFromCard();
    });
    actions->connectAction(u"card_slot_create_csr"_s, q, [this]() {
        createCSR();
    });
}

const SmartCardWidget *SmartCardsWidget::Private::currentCardWidget() const
{
    return qobject_cast<const SmartCardWidget *>(mTabWidget->currentWidget());
}

AppType SmartCardsWidget::Private::currentCardType() const
{
    if (const SmartCardWidget *widget = currentCardWidget()) {
        return widget->cardType();
    }
    return AppType::NoApp;
}

std::string SmartCardsWidget::Private::currentSerialNumber() const
{
    if (const SmartCardWidget *widget = currentCardWidget()) {
        return widget->serialNumber();
    }
    return {};
}

std::string SmartCardsWidget::Private::currentCardSlot() const
{
    if (const SmartCardWidget *widget = currentCardWidget()) {
        return widget->currentCardSlot();
    }
    return {};
}

GpgME::Key SmartCardsWidget::Private::currentCertificate() const
{
    if (const SmartCardWidget *widget = currentCardWidget()) {
        return widget->currentCertificate();
    }
    return {};
}

void SmartCardsWidget::Private::cardAddedOrChanged(const std::string &serialNumber, const std::string &appName)
{
    if (appName == SmartCard::NetKeyCard::AppName) {
        cardAddedOrChanged<NetKeyCard, NetKeyWidget>(serialNumber);
    } else if (appName == SmartCard::OpenPGPCard::AppName) {
        cardAddedOrChanged<OpenPGPCard, PGPCardWidget>(serialNumber);
    } else if (appName == SmartCard::PIVCard::AppName) {
        cardAddedOrChanged<PIVCard, PIVCardWidget>(serialNumber);
    } else if (appName == SmartCard::P15Card::AppName) {
        cardAddedOrChanged<P15Card, P15CardWidget>(serialNumber);
    } else {
        qCWarning(KLEOPATRA_LOG) << "SmartCardsWidget::Private::cardAddedOrChanged:"
                                 << "App" << appName.c_str() << "is not supported";
    }
}

namespace
{
static QString getCardLabel(const std::shared_ptr<Card> &card)
{
    if (!card->cardHolder().isEmpty()) {
        return i18nc("@title:tab smartcard application - name of card holder - serial number of smartcard",
                     "%1 - %2 - %3",
                     displayAppName(card->appName()),
                     card->cardHolder(),
                     card->displaySerialNumber());
    } else {
        return i18nc("@title:tab smartcard application - serial number of smartcard", "%1 - %2", displayAppName(card->appName()), card->displaySerialNumber());
    }
}
}

template<typename C, typename W>
void SmartCardsWidget::Private::cardAddedOrChanged(const std::string &serialNumber)
{
    const auto card = ReaderStatus::instance()->getCard<C>(serialNumber);
    if (!card) {
        qCWarning(KLEOPATRA_LOG) << "SmartCardsWidget::Private::cardAddedOrChanged:"
                                 << "New or changed card" << serialNumber.c_str() << "with app" << C::AppName.c_str() << "not found";
        return;
    }
    W *cardWidget = dynamic_cast<W *>(mCardWidgets.value({serialNumber, C::AppName}).data());
    if (!cardWidget) {
        cardWidget = new W;
        mCardWidgets.insert({serialNumber, C::AppName}, cardWidget);
        mTabWidget->addTab(cardWidget, getCardLabel(card));
        if (mCardWidgets.size() == 1) {
            mStack->setCurrentWidget(mTabWidget);
        }
    }
    cardWidget->setCard(card.get());
}

void SmartCardsWidget::Private::cardRemoved(const std::string &serialNumber, const std::string &appName)
{
    QWidget *cardWidget = mCardWidgets.take({serialNumber, appName});
    if (cardWidget) {
        const int index = mTabWidget->indexOf(cardWidget);
        if (index != -1) {
            mTabWidget->removeTab(index);
        }
        delete cardWidget;
    }
    if (mCardWidgets.empty()) {
        mStack->setCurrentWidget(mPlaceHolderWidget);
    }
}

void SmartCardsWidget::Private::enableCurrentWidget()
{
    mTabWidget->currentWidget()->setEnabled(true);
}

void SmartCardsWidget::Private::disableCurrentWidget()
{
    mTabWidget->currentWidget()->setEnabled(false);
}

void SmartCardsWidget::Private::startCommand(Command *cmd)
{
    Q_ASSERT(cmd);
    disableCurrentWidget();
    connect(cmd, &Command::finished, q, [this]() {
        enableCurrentWidget();
    });
    cmd->start();
}

void SmartCardsWidget::Private::generateCardKeysAndOpenPGPCertificate()
{
    Q_ASSERT(currentCardType() == AppType::OpenPGPApp);
    startCommand(new GenerateOpenPGPCardKeysAndCertificateCommand(currentSerialNumber(), q->window()));
}

void SmartCardsWidget::Private::createOpenPGPCertificate()
{
    const auto app = currentCardType();
    Q_ASSERT(app == AppType::NetKeyApp || app == AppType::PIVApp);
    const std::string serialNumber = currentSerialNumber();
    Q_ASSERT(!serialNumber.empty());
    startCommand(new CreateOpenPGPKeyFromCardKeysCommand(serialNumber, appName(app), q->window()));
}

void SmartCardsWidget::Private::changePin(const std::string &keyRef, ChangePinCommand::ChangePinMode mode)
{
    const auto app = currentCardType();
    Q_ASSERT(app == AppType::NetKeyApp || app == AppType::OpenPGPApp || app == AppType::PIVApp);
    const std::string serialNumber = currentSerialNumber();
    Q_ASSERT(!serialNumber.empty());
    auto cmd = new ChangePinCommand(serialNumber, appName(app), q->window());
    cmd->setKeyRef(keyRef);
    cmd->setMode(mode);
    if (app == AppType::NetKeyApp) {
        const Card *card = currentCardWidget()->card();
        if ((keyRef == NetKeyCard::nksPinKeyRef() && card->hasNKSNullPin()) //
            || (keyRef == NetKeyCard::sigGPinKeyRef() && card->hasSigGNullPin())) {
            cmd->setMode(ChangePinCommand::NullPinMode);
        }
    }
    startCommand(cmd);
}

void SmartCardsWidget::Private::unblockOpenPGPCard()
{
    Q_ASSERT(currentCardType() == AppType::OpenPGPApp);
    const auto pinCounters = currentCardWidget()->card()->pinCounters();
    const bool pukIsAvailable = (pinCounters.size() == 3) && (pinCounters[1] > 0);
    if (pukIsAvailable) {
        // unblock card with the PUK
        changePin(OpenPGPCard::resetCodeKeyRef());
    } else {
        // unblock card with the Admin PIN
        changePin(OpenPGPCard::pinKeyRef(), ChangePinCommand::ResetMode);
    }
}

void SmartCardsWidget::Private::changeCardholder()
{
    const auto app = currentCardType();
    Q_ASSERT(app == AppType::OpenPGPApp);
    const std::string serialNumber = currentSerialNumber();
    Q_ASSERT(!serialNumber.empty());
    QString text = currentCardWidget()->card()->cardHolder();
    while (true) {
        bool ok = false;
        text = QInputDialog::getText(q,
                                     i18nc("@title:window", "Change Cardholder"),
                                     i18nc("@label ", "Enter the new cardholder name:"),
                                     QLineEdit::Normal,
                                     text,
                                     &ok,
                                     Qt::WindowFlags(),
                                     Qt::ImhLatinOnly);
        if (!ok) {
            return;
        }
        // Some additional restrictions imposed by gnupg
        if (text.contains(u'<')) {
            KMessageBox::error(q, i18nc("@info", "The \"<\" character may not be used."));
            continue;
        }
        if (text.contains("  "_L1)) {
            KMessageBox::error(q, i18nc("@info", "Double spaces are not allowed"));
            continue;
        }
        if (text.size() > 38) {
            KMessageBox::error(q, i18nc("@info", "The size of the name may not exceed 38 characters."));
            continue;
        }
        break;
    }
    auto parts = text.split(u' ');
    const auto lastName = parts.takeLast();
    const QString formatted = lastName + "<<"_L1 + parts.join(u'<');

    const auto pgpCard = ReaderStatus::instance()->getCard<OpenPGPCard>(serialNumber);
    if (!pgpCard) {
        KMessageBox::error(q, i18nc("@info", "Failed to find the OpenPGP card with the serial number: %1", QString::fromStdString(serialNumber)));
        return;
    }

    const QByteArray command = QByteArrayLiteral("SCD SETATTR DISP-NAME ") + formatted.toUtf8();
    ReaderStatus::mutableInstance()->startSimpleTransaction(pgpCard, command, q, [this, serialNumber, app](const GpgME::Error &err) {
        if (err) {
            KMessageBox::error(q, i18nc("@info", "Name change failed: %1", Formatting::errorAsString(err)));
        } else if (!err.isCanceled()) {
            ReaderStatus::mutableInstance()->updateCard(serialNumber, appName(app));
        }
    });
}

void SmartCardsWidget::Private::changePublicKeyUrl()
{
    const auto app = currentCardType();
    Q_ASSERT(app == AppType::OpenPGPApp);
    const std::string serialNumber = currentSerialNumber();
    Q_ASSERT(!serialNumber.empty());
    QString text = currentCardWidget()->card()->publicKeyUrl();
    while (true) {
        bool ok = false;
        text = QInputDialog::getText(q,
                                     i18nc("@title:window", "Change Public Key URL"),
                                     i18nc("@label", "Enter the new public key URL:"),
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
            KMessageBox::error(q, i18nc("@info", "The size of the URL may not exceed 254 characters."));
            continue;
        }
        break;
    }

    const auto pgpCard = ReaderStatus::instance()->getCard<OpenPGPCard>(serialNumber);
    if (!pgpCard) {
        KMessageBox::error(q, i18nc("@info", "Failed to find the OpenPGP card with the serial number: %1", QString::fromStdString(serialNumber)));
        return;
    }

    const QByteArray command = QByteArrayLiteral("SCD SETATTR PUBKEY-URL ") + text.toUtf8();
    ReaderStatus::mutableInstance()->startSimpleTransaction(pgpCard, command, q, [this, serialNumber, app](const GpgME::Error &err) {
        if (err) {
            KMessageBox::error(q, i18nc("@info", "URL change failed: %1", Formatting::errorAsString(err)));
        } else if (!err.isCanceled()) {
            ReaderStatus::mutableInstance()->updateCard(serialNumber, appName(app));
        }
    });
}

void SmartCardsWidget::Private::setPIVAdminKey()
{
    Q_ASSERT(currentCardType() == AppType::PIVApp);
    startCommand(new SetPIVCardApplicationAdministrationKeyCommand(currentSerialNumber(), q->window()));
}

void SmartCardsWidget::Private::showCertificateDetails()
{
    const Key certificate = currentCertificate();
    if (!certificate.isNull()) {
        auto cmd = new DetailsCommand(certificate);
        cmd->setParentWidget(q->window());
        cmd->start();
    }
}

static Command *createGenerateKeyCommand(AppType app, const std::string &serialNumber, const std::string &keyRef, QWidget *parent)
{
    Q_ASSERT(app == AppType::OpenPGPApp || app == AppType::PIVApp);
    Q_ASSERT(!serialNumber.empty());
    if (app == AppType::OpenPGPApp) {
        return new OpenPGPGenerateCardKeyCommand(keyRef, serialNumber, parent);
    }
    auto cmd = new PIVGenerateCardKeyCommand(serialNumber, parent);
    cmd->setKeyRef(keyRef);
    return cmd;
}

void SmartCardsWidget::Private::generateKey()
{
    startCommand(createGenerateKeyCommand(currentCardType(), currentSerialNumber(), currentCardSlot(), q->window()));
}

void SmartCardsWidget::Private::createCSR()
{
    const auto app = currentCardType();
    Q_ASSERT(app == AppType::NetKeyApp || app == AppType::OpenPGPApp || app == AppType::PIVApp);
    const std::string serialNumber = currentSerialNumber();
    Q_ASSERT(!serialNumber.empty());
    const std::string keyRef = currentCardSlot();
    startCommand(new CreateCSRForCardKeyCommand(keyRef, serialNumber, appName(app), q->window()));
}

void SmartCardsWidget::Private::writeCertificateToCard()
{
    Q_ASSERT(currentCardType() == AppType::PIVApp);
    const std::string serialNumber = currentSerialNumber();
    Q_ASSERT(!serialNumber.empty());
    const std::string keyRef = currentCardSlot();
    startCommand(new CertificateToPIVCardCommand(keyRef, serialNumber, q->window()));
}

void SmartCardsWidget::Private::readCertificateFromCard()
{
    Q_ASSERT(currentCardType() == AppType::PIVApp);
    const std::string serialNumber = currentSerialNumber();
    Q_ASSERT(!serialNumber.empty());
    const std::string keyRef = currentCardSlot();
    startCommand(new ImportCertificateFromPIVCardCommand(keyRef, serialNumber, q->window()));
}

void SmartCardsWidget::Private::writeKeyToCard()
{
    Q_ASSERT(currentCardType() == AppType::PIVApp);
    const std::string serialNumber = currentSerialNumber();
    Q_ASSERT(!serialNumber.empty());
    const std::string keyRef = currentCardSlot();
    startCommand(new KeyToCardCommand(keyRef, serialNumber, PIVCard::AppName, q->window()));
}

SmartCardsWidget::SmartCardsWidget(QWidget *parent)
    : QWidget{parent}
    , d{std::make_unique<Private>(this)}
{
    connect(ReaderStatus::instance(), &ReaderStatus::currentActionChanged, this, &SmartCardsWidget::updateReloadButton);
    updateReloadButton();
}

SmartCardsWidget::~SmartCardsWidget() = default;

void SmartCardsWidget::showCards(const std::vector<std::shared_ptr<Kleo::SmartCard::Card>> &cards)
{
    for (const auto &card : cards) {
        d->cardAddedOrChanged(card->serialNumber(), card->appName());
    }
}

void SmartCardsWidget::reload()
{
    ReaderStatus::mutableInstance()->updateStatus();
}

void SmartCardsWidget::updateReloadButton()
{
    d->mReloadButton->setEnabled(ReaderStatus::instance()->currentAction() != ReaderStatus::UpdateCards);
}

#include "smartcardswidget.moc"

#include "moc_smartcardswidget.cpp"
