// SPDX-FileCopyrightText: 2024 g10 Code GmbH
// SPDX-FileContributor: Tobias Fella <tobias.fella@gnupg.com>
// SPDX-License-Identifier: GPL-2.0-or-later

#include <config-kleopatra.h>

#include "certificatetocardcommand.h"

#include "cardcommand_p.h"
#include "commands/exportpaperkeycommand.h"
#include "dialogs/copytosmartcarddialog.h"
#include "exportsecretkeycommand.h"
#include "smartcard/algorithminfo.h"
#include "smartcard/openpgpcard.h"
#include "smartcard/readerstatus.h"
#include "smartcard/utils.h"
#include "utils/applicationstate.h"

#include <Libkleo/Algorithm>
#include <Libkleo/Formatting>
#include <Libkleo/GnuPG>
#include <Libkleo/KeyCache>

#include <QGpgME/ExportJob>
#include <gpgme.h>

#include <KFileUtils>
#include <KLocalizedString>

#include <QDateTime>
#include <QDir>
#include <QStandardPaths>
#include <QStringList>

#include "kleopatra_debug.h"

using namespace Kleo;
using namespace Kleo::Commands;
using namespace Kleo::SmartCard;
using namespace GpgME;

namespace
{
struct GripAndSlot {
    std::string keygrip;
    std::string slot;
};
}

namespace
{

bool cardSupportsKeyAlgorithm(const std::shared_ptr<const Card> &card, const std::string &keyAlgo)
{
    if (card->appName() == OpenPGPCard::AppName) {
        const auto pgpCard = static_cast<const OpenPGPCard *>(card.get());
        const auto cardAlgos = pgpCard->supportedAlgorithms();
        return std::ranges::any_of(cardAlgos, [keyAlgo](const auto &algo) {
            return (keyAlgo == algo.id) //
                || (keyAlgo == OpenPGPCard::getAlgorithmName(algo.id, OpenPGPCard::pgpEncKeyRef()))
                || (keyAlgo == OpenPGPCard::getAlgorithmName(algo.id, OpenPGPCard::pgpSigKeyRef()));
        });
    }
    return false;
}

QString cardDisplayName(const std::shared_ptr<const Card> &card)
{
    return i18nc("smartcard application - serial number of smartcard", "%1 - %2", displayAppName(card->appName()), card->displaySerialNumber());
}
}

class CertificateToCardCommand::Private : public CardCommand::Private
{
    friend class ::Kleo::Commands::CertificateToCardCommand;
    CertificateToCardCommand *q_func() const
    {
        return static_cast<CertificateToCardCommand *>(q);
    }

public:
    explicit Private(CertificateToCardCommand *qq);

private:
    enum Confirmation {
        AskForConfirmation,
        SkipConfirmation,
    };

    void start();

    void startKeyToOpenPGPCard();

    void keyToCardDone(const GpgME::Error &err);

    void updateDone();

    void keyHasBeenCopiedToCard();

    void startDeleteSecretKeyLocally(Confirmation confirmation);
    void deleteSecretKeyLocallyFinished(const GpgME::Error &err);

    void copyNextSubkey();
    void deleteNextSubkey();

private:
    std::vector<GripAndSlot> gripsAndSlots;
    std::string appName;
    std::vector<GpgME::Subkey> subkeys;
    std::vector<GpgME::Subkey> remainingSubkeys;
    std::string cardSlot;
    QMetaObject::Connection updateConnection;
    bool removeSecretKey = false;
    QString exportPath;
};

CertificateToCardCommand::Private *CertificateToCardCommand::d_func()
{
    return static_cast<Private *>(d.get());
}
const CertificateToCardCommand::Private *CertificateToCardCommand::d_func() const
{
    return static_cast<const Private *>(d.get());
}

#define q q_func()
#define d d_func()

CertificateToCardCommand::Private::Private(CertificateToCardCommand *qq)
    : CardCommand::Private(qq, "", nullptr)
{
}

namespace
{
static std::shared_ptr<Card> getEmptyCard(const Key &key)
{
    for (const auto &card : ReaderStatus::instance()->getCards()) {
        const auto &subkeys = key.subkeys();
        if (card->appName() != OpenPGPCard::AppName || card->hasSigningKey() || card->hasEncryptionKey() || card->hasAuthenticationKey()) {
            continue;
        }
        if (std::all_of(subkeys.begin(), subkeys.end(), [card](const auto &subkey) {
                return cardSupportsKeyAlgorithm(card, subkey.algoName());
            })) {
            return card;
        }
    }

    return std::shared_ptr<Card>();
}
}

void CertificateToCardCommand::Private::start()
{
    qCDebug(KLEOPATRA_LOG) << "CertificateToCardCommand::Private::start()";

    if (key().isNull() || key().protocol() != GpgME::OpenPGP) {
        finished();
        return;
    }

    const auto card = getEmptyCard(key());
    if (!card) {
        error(i18nc("@info", "No empty smart card was found."));
        finished();
        return;
    }
    Dialogs::CopyToSmartcardDialog dialog(parentWidgetOrView());
    dialog.setKey(key());
    dialog.setCardDisplayName(cardDisplayName(card));
    dialog.exec();

    if (dialog.result() == QDialog::Rejected) {
        finished();
        return;
    }

    setSerialNumber(card->serialNumber());
    appName = card->appName();

    auto choice = dialog.backupChoice();

    if (choice != Dialogs::CopyToSmartcardDialog::KeepKey) {
        removeSecretKey = true;
    }

    if (choice == Dialogs::CopyToSmartcardDialog::FileBackup) {
        auto command = new ExportSecretKeyCommand(key());
        command->setInteractive(false);

        auto name = Formatting::prettyName(key());
        name.remove(QRegularExpression(QStringLiteral("[:/\\\\")));
        if (name.isEmpty()) {
            name = Formatting::prettyEMail(key());
        }

        auto filename = QStringLiteral("%1_%2_secret.asc").arg(name, Formatting::prettyKeyID(key().shortKeyID()));
        const auto dir = QDir{QStandardPaths::writableLocation(QStandardPaths::DocumentsLocation)};
        if (dir.exists(filename)) {
            filename = KFileUtils::suggestName(QUrl::fromLocalFile(dir.path()), filename);
        }
        exportPath = dir.absoluteFilePath(filename);
        command->setFileName(exportPath);
        command->start();
        connect(command, &Command::finished, q, [this, command]() {
            if (!command->success()) {
                // Error messsages are shown by the export command
                finished();
                return;
            }
            startKeyToOpenPGPCard();
        });
    } else if (choice == Dialogs::CopyToSmartcardDialog::PrintBackup) {
        auto exportPaperKey = new ExportPaperKeyCommand(key());
        exportPaperKey->start();
        connect(exportPaperKey, &ExportPaperKeyCommand::finished, q, [this, exportPaperKey]() {
            if (!exportPaperKey->success()) {
                return;
            }
            startKeyToOpenPGPCard();
        });
    } else {
        startKeyToOpenPGPCard();
    }
}

namespace
{
static std::string getOpenPGPCardSlotForKey(const GpgME::Subkey &subKey)
{
    if ((subKey.canSign() || subKey.canCertify()) && !subKey.canEncrypt() && !subKey.canAuthenticate()) {
        // Signing only
        return OpenPGPCard::pgpSigKeyRef();
    }
    if (subKey.canEncrypt() && !(subKey.canSign() || subKey.canCertify()) && !subKey.canAuthenticate()) {
        // Encrypt only
        return OpenPGPCard::pgpEncKeyRef();
    }
    if (subKey.canAuthenticate() && !(subKey.canSign() || subKey.canCertify()) && !subKey.canEncrypt()) {
        // Auth only
        return OpenPGPCard::pgpAuthKeyRef();
    }
    return {};
}
}

void CertificateToCardCommand::Private::startKeyToOpenPGPCard()
{
    qCDebug(KLEOPATRA_LOG) << "CertificateToCardCommand::Private::startKeyToOpenPGPCard()";

    const auto card = SmartCard::ReaderStatus::instance()->getCard(serialNumber(), appName);
    if (!card) {
        error(i18n("Failed to find the card with the serial number: %1", QString::fromStdString(serialNumber())));
        finished();
        return;
    }

    subkeys = key().subkeys();
    Kleo::erase_if(subkeys, [](const auto &key) {
        return key.canRenc();
    });
    remainingSubkeys = subkeys;

    for (const auto &subkey : subkeys) {
        if (getOpenPGPCardSlotForKey(subkey).empty()) {
            error(i18nc("@info", "No slot found for subkey %1 on the smart card.", Formatting::prettyID(subkey.fingerprint())));
            finished();
            return;
        }
    }

    copyNextSubkey();
}

void CertificateToCardCommand::Private::copyNextSubkey()
{
    const auto subkey = remainingSubkeys[remainingSubkeys.size() - 1];
    remainingSubkeys.pop_back();
    auto cardSlot = getOpenPGPCardSlotForKey(subkey);

    gripsAndSlots.push_back(GripAndSlot{
        std::string(subkey.keyGrip()),
        cardSlot,
    });

    const auto pgpCard = SmartCard::ReaderStatus::instance()->getCard<OpenPGPCard>(serialNumber());
    if (!pgpCard) {
        error(i18n("Failed to find the OpenPGP card with the serial number: %1", QString::fromStdString(serialNumber())));
        finished();
        return;
    }

    const auto time = QDateTime::fromSecsSinceEpoch(quint32(subkey.creationTime()), QTimeZone::utc());
    const auto timestamp = time.toString(QStringLiteral("yyyyMMdd'T'HHmmss"));
    const QString cmd = QStringLiteral("KEYTOCARD --force %1 %2 %3 %4")
                            .arg(QString::fromLatin1(subkey.keyGrip()), QString::fromStdString(serialNumber()), QString::fromStdString(cardSlot), timestamp);
    ReaderStatus::mutableInstance()->startSimpleTransaction(pgpCard, cmd.toUtf8(), q_func(), [this](const GpgME::Error &err) {
        if (!err && !err.isCanceled() && !remainingSubkeys.empty()) {
            QMetaObject::invokeMethod(
                q,
                [this]() {
                    copyNextSubkey();
                },
                Qt::QueuedConnection);
        } else {
            keyToCardDone(err);
        }
    });
}

void CertificateToCardCommand::Private::updateDone()
{
    disconnect(updateConnection);
    const auto card = SmartCard::ReaderStatus::instance()->getCard(serialNumber(), appName);
    if (!card) {
        error(i18n("Failed to find the card with the serial number: %1", QString::fromStdString(serialNumber())));
        finished();
        return;
    }

    for (const auto &gripAndSlot : gripsAndSlots) {
        const std::string keyGripOnCard = card->keyInfo(gripAndSlot.slot).grip;
        if (keyGripOnCard != gripAndSlot.keygrip) {
            qCWarning(KLEOPATRA_LOG) << q << __func__ << "KEYTOCARD succeeded, but key on card doesn't match copied key";
            error(i18nc("@info", "Copying the key to the card failed."));
            finished();
            return;
        }
    }

    keyHasBeenCopiedToCard();
}

void CertificateToCardCommand::Private::keyHasBeenCopiedToCard()
{
    if (exportPath.isEmpty()) {
        information(xi18nc("@info", "<para>The key was copied to the smart card.</para>"));
    } else {
        information(
            xi18nc("@info", "<para>The key was copied to the smart card.</para><para>A backup was exported to <filename>%1</filename></para>", exportPath));
    }

    if (removeSecretKey) {
        startDeleteSecretKeyLocally(AskForConfirmation);
    } else {
        finished();
    }
}

void CertificateToCardCommand::Private::startDeleteSecretKeyLocally(Confirmation confirmation)
{
    if (confirmation == AskForConfirmation) {
        const auto answer = KMessageBox::questionTwoActions(parentWidgetOrView(),
                                                            xi18nc("@info", "Do you really want to delete the copy of the secret key stored on this computer?"),
                                                            i18nc("@title:window", "Confirm Deletion"),
                                                            KStandardGuiItem::del(),
                                                            KStandardGuiItem::cancel(),
                                                            {},
                                                            KMessageBox::Notify | KMessageBox::Dangerous);
        if (answer != KMessageBox::ButtonCode::PrimaryAction) {
            finished();
            return;
        }
    }

    remainingSubkeys = subkeys;

    deleteNextSubkey();
}

void CertificateToCardCommand::Private::deleteNextSubkey()
{
    const auto card = SmartCard::ReaderStatus::instance()->getCard(serialNumber(), appName);
    if (!card) {
        error(i18n("Failed to find the card with the serial number: %1", QString::fromStdString(serialNumber())));
        finished();
        return;
    }
    const auto subkey = remainingSubkeys[remainingSubkeys.size() - 1];
    remainingSubkeys.pop_back();

    const auto cmd = QByteArray{"DELETE_KEY --force "} + subkey.keyGrip();
    ReaderStatus::mutableInstance()->startSimpleTransaction(card, cmd, q, [this](const GpgME::Error &err) {
        if (err || err.isCanceled() || remainingSubkeys.empty()) {
            deleteSecretKeyLocallyFinished(err);
        } else {
            QMetaObject::invokeMethod(
                q,
                [this]() {
                    deleteNextSubkey();
                },
                Qt::QueuedConnection);
        }
    });
}

void CertificateToCardCommand::Private::deleteSecretKeyLocallyFinished(const GpgME::Error &err)
{
    if (err) {
        error(xi18nc("@info",
                     "<para>Failed to delete the copy of the secret key stored on this computer:</para><para><message>%1</message></para>",
                     Formatting::errorAsString(err)));
    }
    ReaderStatus::mutableInstance()->updateStatus();
    finished();
}

CertificateToCardCommand::CertificateToCardCommand(QAbstractItemView *view, KeyListController *controller)
    : CardCommand(new Private(this), view)
{
    Q_UNUSED(controller);
}

CertificateToCardCommand::~CertificateToCardCommand()
{
    qCDebug(KLEOPATRA_LOG) << "CertificateToCardCommand::~CertificateToCardCommand()";
}

void CertificateToCardCommand::Private::keyToCardDone(const GpgME::Error &err)
{
    if (err.isCanceled()) {
        finished();
        return;
    }

    if (err) {
        error(xi18nc("@info", "<para>Copying the key to the card failed:</para><para><message>%1</message></para>", Formatting::errorAsString(err)));
    }

    updateConnection = connect(ReaderStatus::instance(), &ReaderStatus::updateFinished, q, [this]() {
        updateDone();
    });
    ReaderStatus::mutableInstance()->updateCard(serialNumber(), appName);
}

void CertificateToCardCommand::doStart()
{
    qCDebug(KLEOPATRA_LOG) << "CertificateToCardCommand::doStart()";

    d->start();
}

void CertificateToCardCommand::doCancel()
{
}

#undef q_func
#undef d_func

#include "moc_certificatetocardcommand.cpp"
