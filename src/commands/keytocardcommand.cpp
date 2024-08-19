/* commands/keytocardcommand.cpp

    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2017 Bundesamt für Sicherheit in der Informationstechnik
    SPDX-FileContributor: Intevation GmbH
    SPDX-FileCopyrightText: 2020,2022 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include <config-kleopatra.h>

#include "keytocardcommand.h"

#include "cardcommand_p.h"

#include "authenticatepivcardapplicationcommand.h"

#include "smartcard/algorithminfo.h"
#include "smartcard/openpgpcard.h"
#include "smartcard/pivcard.h"
#include "smartcard/readerstatus.h"
#include "smartcard/utils.h"
#include <utils/applicationstate.h>
#include <utils/filedialog.h>

#include <Libkleo/Algorithm>
#include <Libkleo/Dn>
#include <Libkleo/Formatting>
#include <Libkleo/GnuPG>
#include <Libkleo/KeyCache>
#include <Libkleo/KeySelectionDialog>

#include <KLocalizedString>

#include <QDateTime>
#include <QDir>
#include <QInputDialog>
#include <QSaveFile>
#include <QStringList>

#include <gpg-error.h>
#if GPG_ERROR_VERSION_NUMBER >= 0x12400 // 1.36
#define GPG_ERROR_HAS_NO_AUTH
#endif

#include "kleopatra_debug.h"

using namespace Kleo;
using namespace Kleo::Commands;
using namespace Kleo::SmartCard;
using namespace GpgME;

namespace
{
QString cardDisplayName(const std::shared_ptr<const Card> &card)
{
    return i18nc("smartcard application - serial number of smartcard", "%1 - %2", displayAppName(card->appName()), card->displaySerialNumber());
}
}

class KeyToCardCommand::Private : public CardCommand::Private
{
    friend class ::Kleo::Commands::KeyToCardCommand;
    KeyToCardCommand *q_func() const
    {
        return static_cast<KeyToCardCommand *>(q);
    }

public:
    explicit Private(KeyToCardCommand *qq, const GpgME::Subkey &subkey);
    explicit Private(KeyToCardCommand *qq, const std::string &slot, const std::string &serialNumber, const std::string &appName, QWidget *parent);

private:
    enum Confirmation {
        AskForConfirmation,
        SkipConfirmation,
    };

    void start();

    void startKeyToOpenPGPCard();

    Subkey getSubkeyToTransferToPIVCard(const std::string &cardSlot, const std::shared_ptr<PIVCard> &card);
    void startKeyToPIVCard();

    void authenticate();
    void authenticationFinished();
    void authenticationCanceled();

    void keyToCardDone(const GpgME::Error &err);
    void keyToPIVCardDone(const GpgME::Error &err);

    void updateDone();

    void keyHasBeenCopiedToCard();
    void backupHasBeenCreated(const QString &backupFilename);

    QString backupKey();
    std::vector<QByteArray> readSecretKeyFile();
    bool writeSecretKeyBackup(const QString &filename, const std::vector<QByteArray> &keydata);

    void startDeleteSecretKeyLocally(Confirmation confirmation);
    void deleteSecretKeyLocallyFinished(const GpgME::Error &err);

private:
    std::string appName;
    GpgME::Subkey subkey;
    std::string cardSlot;
    bool overwriteExistingAlreadyApproved = false;
    bool hasBeenCanceled = false;
    QMetaObject::Connection updateConnection;
};

KeyToCardCommand::Private *KeyToCardCommand::d_func()
{
    return static_cast<Private *>(d.get());
}
const KeyToCardCommand::Private *KeyToCardCommand::d_func() const
{
    return static_cast<const Private *>(d.get());
}

#define q q_func()
#define d d_func()

KeyToCardCommand::Private::Private(KeyToCardCommand *qq, const GpgME::Subkey &subkey_)
    : CardCommand::Private(qq, "", nullptr)
    , subkey(subkey_)
{
}

KeyToCardCommand::Private::Private(KeyToCardCommand *qq, const std::string &slot, const std::string &serialNumber, const std::string &appName_, QWidget *parent)
    : CardCommand::Private(qq, serialNumber, parent)
    , appName(appName_)
    , cardSlot(slot)
{
}

namespace
{
static std::shared_ptr<Card> getCardToTransferSubkeyTo(const Subkey &subkey, QWidget *parent)
{
    const std::vector<std::shared_ptr<Card>> suitableCards = KeyToCardCommand::getSuitableCards(subkey);
    if (suitableCards.empty()) {
        return std::shared_ptr<Card>();
    } else if (suitableCards.size() == 1) {
        return suitableCards[0];
    }

    QStringList options;
    for (const auto &card : suitableCards) {
        options.push_back(cardDisplayName(card));
    }

    bool ok;
    const QString choice = QInputDialog::getItem(parent,
                                                 i18n("Select Card"),
                                                 i18n("Please select the card the key should be written to:"),
                                                 options,
                                                 /* current= */ 0,
                                                 /* editable= */ false,
                                                 &ok);
    if (!ok) {
        return std::shared_ptr<Card>();
    }
    const int index = options.indexOf(choice);
    return suitableCards[index];
}
}

void KeyToCardCommand::Private::start()
{
    qCDebug(KLEOPATRA_LOG) << "KeyToCardCommand::Private::start()";

    if (!subkey.isNull() && serialNumber().empty()) {
        const auto card = getCardToTransferSubkeyTo(subkey, parentWidgetOrView());
        if (!card) {
            finished();
            return;
        }
        setSerialNumber(card->serialNumber());
        appName = card->appName();
    }

    const auto card = SmartCard::ReaderStatus::instance()->getCard(serialNumber(), appName);
    if (!card) {
        error(i18n("Failed to find the card with the serial number: %1", QString::fromStdString(serialNumber())));
        finished();
        return;
    }

    if (card->appName() == SmartCard::OpenPGPCard::AppName) {
        startKeyToOpenPGPCard();
    } else if (card->appName() == SmartCard::PIVCard::AppName) {
        startKeyToPIVCard();
    } else {
        error(xi18nc("@info", "Sorry! Writing keys to the card <emphasis>%1</emphasis> is not supported.", cardDisplayName(card)));
        finished();
        return;
    }
}

namespace
{
static std::string getOpenPGPCardSlotForKey(const GpgME::Subkey &subKey, QWidget *parent)
{
    // Check if we need to ask the user for the slot
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
    // Multiple uses, ask user.
    QStringList options;
    std::vector<std::string> cardSlots;

    if (subKey.canSign() || subKey.canCertify()) {
        options.push_back(i18nc("@item:inlistbox", "Signature"));
        cardSlots.push_back(OpenPGPCard::pgpSigKeyRef());
    }
    if (subKey.canEncrypt()) {
        options.push_back(i18nc("@item:inlistbox", "Encryption"));
        cardSlots.push_back(OpenPGPCard::pgpEncKeyRef());
    }
    if (subKey.canAuthenticate()) {
        options.push_back(i18nc("@item:inlistbox", "Authentication"));
        cardSlots.push_back(OpenPGPCard::pgpAuthKeyRef());
    }

    bool ok;
    const QString choice = QInputDialog::getItem(parent,
                                                 i18n("Select Card Slot"),
                                                 i18n("Please select the card slot the key should be written to:"),
                                                 options,
                                                 /* current= */ 0,
                                                 /* editable= */ false,
                                                 &ok);
    const int choiceIndex = options.indexOf(choice);
    if (ok && choiceIndex >= 0) {
        return cardSlots[choiceIndex];
    } else {
        return {};
    }
}
}

void KeyToCardCommand::Private::startKeyToOpenPGPCard()
{
    qCDebug(KLEOPATRA_LOG) << "KeyToCardCommand::Private::startKeyToOpenPGPCard()";

    const auto pgpCard = SmartCard::ReaderStatus::instance()->getCard<OpenPGPCard>(serialNumber());
    if (!pgpCard) {
        error(i18n("Failed to find the OpenPGP card with the serial number: %1", QString::fromStdString(serialNumber())));
        finished();
        return;
    }

    if (subkey.isNull()) {
        finished();
        return;
    }
    if (subkey.parent().protocol() != GpgME::OpenPGP) {
        error(i18n("Sorry! This key cannot be transferred to an OpenPGP card."));
        finished();
        return;
    }

    cardSlot = getOpenPGPCardSlotForKey(subkey, parentWidgetOrView());
    if (cardSlot.empty()) {
        finished();
        return;
    }

    // Check if we need to do the overwrite warning.
    const std::string existingKey = pgpCard->keyFingerprint(cardSlot);
    if (!existingKey.empty()) {
        const auto encKeyWarning = (cardSlot == OpenPGPCard::pgpEncKeyRef())
            ? i18n("It will no longer be possible to decrypt past communication encrypted for the existing key.")
            : QString{};
        const QString message = i18nc("@info",
                                      "<p>The card <em>%1</em> already contains a key in this slot. Continuing will <b>overwrite</b> that key.</p>"
                                      "<p>If there is no backup the existing key will be irrecoverably lost.</p>",
                                      cardDisplayName(pgpCard))
            + i18n("The existing key has the fingerprint:") + QStringLiteral("<pre>%1</pre>").arg(Formatting::prettyID(existingKey.c_str())) + encKeyWarning;
        const auto choice = KMessageBox::warningContinueCancel(parentWidgetOrView(),
                                                               message,
                                                               i18nc("@title:window", "Overwrite existing key"),
                                                               KGuiItem{i18nc("@action:button", "Overwrite Existing Key")},
                                                               KStandardGuiItem::cancel(),
                                                               QString(),
                                                               KMessageBox::Notify | KMessageBox::Dangerous);
        if (choice != KMessageBox::Continue) {
            finished();
            return;
        }
    }

    // Now do the deed
    const auto time = QDateTime::fromSecsSinceEpoch(quint32(subkey.creationTime()), QTimeZone::utc());
    const auto timestamp = time.toString(QStringLiteral("yyyyMMdd'T'HHmmss"));
    const QString cmd = QStringLiteral("KEYTOCARD --force %1 %2 %3 %4")
                            .arg(QString::fromLatin1(subkey.keyGrip()), QString::fromStdString(serialNumber()), QString::fromStdString(cardSlot), timestamp);
    ReaderStatus::mutableInstance()->startSimpleTransaction(pgpCard, cmd.toUtf8(), q_func(), [this](const GpgME::Error &err) {
        keyToCardDone(err);
    });
}

namespace
{
static std::vector<Key> getSigningCertificates()
{
    std::vector<Key> signingCertificates = KeyCache::instance()->secretKeys();
    const auto it = std::remove_if(signingCertificates.begin(), signingCertificates.end(), [](const Key &key) {
        return !(key.protocol() == GpgME::CMS && !key.subkey(0).isNull() && key.subkey(0).canSign() && !key.subkey(0).canEncrypt() && key.subkey(0).isSecret()
                 && !key.subkey(0).isCardKey());
    });
    signingCertificates.erase(it, signingCertificates.end());
    return signingCertificates;
}

static std::vector<Key> getEncryptionCertificates()
{
    std::vector<Key> encryptionCertificates = KeyCache::instance()->secretKeys();
    const auto it = std::remove_if(encryptionCertificates.begin(), encryptionCertificates.end(), [](const Key &key) {
        return !(key.protocol() == GpgME::CMS && !key.subkey(0).isNull() && key.subkey(0).canEncrypt() && key.subkey(0).isSecret()
                 && !key.subkey(0).isCardKey());
    });
    encryptionCertificates.erase(it, encryptionCertificates.end());
    return encryptionCertificates;
}
}

Subkey KeyToCardCommand::Private::getSubkeyToTransferToPIVCard(const std::string &cardSlot, const std::shared_ptr<PIVCard> & /*card*/)
{
    if (cardSlot != PIVCard::cardAuthenticationKeyRef() && cardSlot != PIVCard::keyManagementKeyRef()) {
        return Subkey();
    }

    const std::vector<Key> certificates = cardSlot == PIVCard::cardAuthenticationKeyRef() ? getSigningCertificates() : getEncryptionCertificates();
    if (certificates.empty()) {
        error(i18n("Sorry! No suitable certificate to write to this card slot was found."));
        return Subkey();
    }

    auto dialog = new KeySelectionDialog(parentWidgetOrView());
    dialog->setWindowTitle(i18nc("@title:window", "Select Certificate"));
    dialog->setText(i18n("Please select the certificate whose key pair you want to write to the card:"));
    dialog->setKeys(certificates);

    if (dialog->exec() == QDialog::Rejected) {
        return Subkey();
    }

    return dialog->selectedKey().subkey(0);
}

void KeyToCardCommand::Private::startKeyToPIVCard()
{
    qCDebug(KLEOPATRA_LOG) << "KeyToCardCommand::Private::startKeyToPIVCard()";

    const auto pivCard = SmartCard::ReaderStatus::instance()->getCard<PIVCard>(serialNumber());
    if (!pivCard) {
        error(i18n("Failed to find the PIV card with the serial number: %1", QString::fromStdString(serialNumber())));
        finished();
        return;
    }

    if (cardSlot != PIVCard::cardAuthenticationKeyRef() && cardSlot != PIVCard::keyManagementKeyRef()) {
        // key to card is only supported for the Card Authentication key and the Key Management key
        finished();
        return;
    }

    if (subkey.isNull()) {
        subkey = getSubkeyToTransferToPIVCard(cardSlot, pivCard);
    }
    if (subkey.isNull()) {
        finished();
        return;
    }
    if (subkey.parent().protocol() != GpgME::CMS) {
        error(i18n("Sorry! This key cannot be transferred to a PIV card."));
        finished();
        return;
    }
    if (!subkey.canEncrypt() && !subkey.canSign()) {
        error(i18n("Sorry! Only encryption keys and signing keys can be transferred to a PIV card."));
        finished();
        return;
    }

    // Check if we need to do the overwrite warning.
    if (!overwriteExistingAlreadyApproved) {
        const std::string existingKey = pivCard->keyInfo(cardSlot).grip;
        if (!existingKey.empty() && (existingKey != subkey.keyGrip())) {
            const QString decryptionWarning = (cardSlot == PIVCard::keyManagementKeyRef())
                ? i18n("It will no longer be possible to decrypt past communication encrypted for the existing key.")
                : QString();
            const QString message = i18nc("@info",
                                          "<p>The card <em>%1</em> already contains a key in this slot. Continuing will <b>overwrite</b> that key.</p>"
                                          "<p>If there is no backup the existing key will be irrecoverably lost.</p>",
                                          cardDisplayName(pivCard))
                + i18n("The existing key has the key grip:") + QStringLiteral("<pre>%1</pre>").arg(QString::fromStdString(existingKey)) + decryptionWarning;
            const auto choice = KMessageBox::warningContinueCancel(parentWidgetOrView(),
                                                                   message,
                                                                   i18nc("@title:window", "Overwrite existing key"),
                                                                   KGuiItem{i18nc("@action:button", "Overwrite Existing Key")},
                                                                   KStandardGuiItem::cancel(),
                                                                   QString(),
                                                                   KMessageBox::Notify | KMessageBox::Dangerous);
            if (choice != KMessageBox::Continue) {
                finished();
                return;
            }
            overwriteExistingAlreadyApproved = true;
        }
    }

    const QString cmd = QStringLiteral("KEYTOCARD --force %1 %2 %3")
                            .arg(QString::fromLatin1(subkey.keyGrip()), QString::fromStdString(serialNumber()))
                            .arg(QString::fromStdString(cardSlot));
    ReaderStatus::mutableInstance()->startSimpleTransaction(pivCard, cmd.toUtf8(), q_func(), [this](const GpgME::Error &err) {
        keyToPIVCardDone(err);
    });
}

void KeyToCardCommand::Private::authenticate()
{
    qCDebug(KLEOPATRA_LOG) << "KeyToCardCommand::authenticate()";

    auto cmd = new AuthenticatePIVCardApplicationCommand(serialNumber(), parentWidgetOrView());
    cmd->setAutoResetCardToOpenPGP(false);
    connect(cmd, &AuthenticatePIVCardApplicationCommand::finished, q, [this]() {
        authenticationFinished();
    });
    connect(cmd, &AuthenticatePIVCardApplicationCommand::canceled, q, [this]() {
        authenticationCanceled();
    });
    cmd->start();
}

void KeyToCardCommand::Private::authenticationFinished()
{
    qCDebug(KLEOPATRA_LOG) << "KeyToCardCommand::authenticationFinished()";
    if (!hasBeenCanceled) {
        startKeyToPIVCard();
    }
}

void KeyToCardCommand::Private::authenticationCanceled()
{
    qCDebug(KLEOPATRA_LOG) << "KeyToCardCommand::authenticationCanceled()";
    hasBeenCanceled = true;
    canceled();
}

void KeyToCardCommand::Private::updateDone()
{
    disconnect(updateConnection);
    const auto card = SmartCard::ReaderStatus::instance()->getCard(serialNumber(), appName);
    if (!card) {
        error(i18n("Failed to find the card with the serial number: %1", QString::fromStdString(serialNumber())));
        finished();
        return;
    }

    const std::string keyGripOnCard = card->keyInfo(cardSlot).grip;
    if (keyGripOnCard != subkey.keyGrip()) {
        qCWarning(KLEOPATRA_LOG) << q << __func__ << "KEYTOCARD succeeded, but key on card doesn't match copied key";
        error(i18nc("@info", "Copying the key to the card failed."));
        finished();
        return;
    }
    keyHasBeenCopiedToCard();
}

void KeyToCardCommand::Private::keyHasBeenCopiedToCard()
{
    const auto answer = KMessageBox::questionTwoActionsCancel(parentWidgetOrView(),
                                                              xi18nc("@info",
                                                                     "<para>The key has been copied to the card.</para>"
                                                                     "<para>You can now delete the copy of the key stored on this computer. "
                                                                     "Optionally, you can first create a backup of the key.</para>"),
                                                              i18nc("@title:window", "Success"),
                                                              KGuiItem{i18nc("@action:button", "Create backup")},
                                                              KGuiItem{i18nc("@action:button", "Delete copy on disk")},
                                                              KGuiItem{i18nc("@action:button", "Keep copy on disk")});
    if (answer == KMessageBox::ButtonCode::PrimaryAction) {
        const QString backupFilename = backupKey();
        if (backupFilename.isEmpty()) {
            // user canceled the backup or there was an error; repeat above question
            QMetaObject::invokeMethod(q, [this]() {
                keyHasBeenCopiedToCard();
            });
        }
        backupHasBeenCreated(backupFilename);
    } else if (answer == KMessageBox::ButtonCode::SecondaryAction) {
        startDeleteSecretKeyLocally(AskForConfirmation);
    } else {
        finished();
    }
}

void KeyToCardCommand::Private::backupHasBeenCreated(const QString &backupFilename)
{
    const auto answer =
        KMessageBox::questionTwoActions(parentWidgetOrView(),
                                        xi18nc("@info",
                                               "<para>The key has been copied to the card and a backup has been written to <filename>%1</filename>.</para>"
                                               "<para>Do you want to delete the copy of the key stored on this computer?</para>",
                                               backupFilename),
                                        i18nc("@title:window", "Success"),
                                        KGuiItem{i18nc("@action:button", "Delete copy on disk")},
                                        KGuiItem{i18nc("@action:button", "Keep copy on disk")});
    if (answer == KMessageBox::ButtonCode::PrimaryAction) {
        // the user has created a backup; don't ask again for confirmation before deleting the copy on disk
        startDeleteSecretKeyLocally(SkipConfirmation);
    } else {
        finished();
    }
}

namespace
{
QString gnupgPrivateKeyBackupExtension()
{
    return QStringLiteral(".gpgsk");
}

QString proposeFilename(const Subkey &subkey)
{
    QString filename;

    const auto key = subkey.parent();
    auto name = Formatting::prettyName(key);
    if (name.isEmpty()) {
        name = Formatting::prettyEMail(key);
    }
    const auto shortKeyID = Formatting::prettyKeyID(key.shortKeyID());
    const auto shortSubkeyID = Formatting::prettyKeyID(QByteArray{subkey.keyID()}.right(8).constData());
    const auto usage = Formatting::usageString(subkey).replace(QLatin1StringView{", "}, QLatin1String{"_"});
    /* Not translated so it's better to use in tutorials etc. */
    filename = ((shortKeyID == shortSubkeyID) //
                    ? QStringView{u"%1_%2_SECRET_KEY_BACKUP_%3"}.arg(name, shortKeyID, usage)
                    : QStringView{u"%1_%2_SECRET_KEY_BACKUP_%3_%4"}.arg(name, shortKeyID, shortSubkeyID, usage));
    filename.replace(u'/', u'_');

    return QDir{ApplicationState::lastUsedExportDirectory()}.filePath(filename + gnupgPrivateKeyBackupExtension());
}

QString requestPrivateKeyBackupFilename(const QString &proposedFilename, QWidget *parent)
{
    auto filename = FileDialog::getSaveFileNameEx(parent,
                                                  i18nc("@title:window", "Backup Secret Key"),
                                                  QStringLiteral("imp"),
                                                  proposedFilename,
                                                  i18nc("description of filename filter", "Secret Key Backup Files") + QLatin1StringView{" (*.gpgsk)"});

    if (!filename.isEmpty()) {
        const QFileInfo fi{filename};
        if (fi.suffix().isEmpty()) {
            filename += gnupgPrivateKeyBackupExtension();
        }
        ApplicationState::setLastUsedExportDirectory(filename);
    }

    return filename;
}
}

QString KeyToCardCommand::Private::backupKey()
{
    static const QByteArray backupInfoName = "Backup-info:";

    auto keydata = readSecretKeyFile();
    if (keydata.empty()) {
        return {};
    }
    const auto filename = requestPrivateKeyBackupFilename(proposeFilename(subkey), parentWidgetOrView());
    if (filename.isEmpty()) {
        return {};
    }

    // remove old backup info
    Kleo::erase_if(keydata, [](const auto &line) {
        return line.startsWith(backupInfoName);
    });
    // prepend new backup info
    const QByteArrayList backupInfo = {
        backupInfoName,
        subkey.keyGrip(),
        QDateTime::currentDateTimeUtc().toString(Qt::ISODate).toUtf8(),
        "Kleopatra",
        Formatting::prettyNameAndEMail(subkey.parent()).toUtf8(),
    };
    keydata.insert(keydata.begin(), backupInfo.join(' ') + '\n');

    if (writeSecretKeyBackup(filename, keydata)) {
        return filename;
    } else {
        return {};
    }
}

std::vector<QByteArray> KeyToCardCommand::Private::readSecretKeyFile()
{
    const auto filename = QString::fromLatin1(subkey.keyGrip()) + QLatin1StringView{".key"};
    const auto path = QDir{Kleo::gnupgPrivateKeysDirectory()}.filePath(filename);

    QFile file{path};
    if (!file.open(QIODevice::ReadOnly | QIODevice::Text)) {
        error(xi18n("Cannot open the private key file <filename>%1</filename> for reading.", path));
        return {};
    }

    std::vector<QByteArray> lines;
    while (!file.atEnd()) {
        lines.push_back(file.readLine());
    }
    if (lines.empty()) {
        error(xi18n("The private key file <filename>%1</filename> is empty.", path));
    }
    return lines;
}

bool KeyToCardCommand::Private::writeSecretKeyBackup(const QString &filename, const std::vector<QByteArray> &keydata)
{
    QSaveFile file{filename};
    // open the file in binary format because we want to write Unix line endings
    if (!file.open(QIODevice::WriteOnly)) {
        error(xi18n("Cannot open the file <filename>%1</filename> for writing.", filename));
        return false;
    }
    for (const auto &line : keydata) {
        file.write(line);
    }
    if (!file.commit()) {
        error(xi18n("Writing the backup of the secret key to <filename>%1</filename> failed.", filename));
        return false;
    };
    return true;
}

void KeyToCardCommand::Private::startDeleteSecretKeyLocally(Confirmation confirmation)
{
    const auto card = SmartCard::ReaderStatus::instance()->getCard(serialNumber(), appName);
    if (!card) {
        error(i18n("Failed to find the card with the serial number: %1", QString::fromStdString(serialNumber())));
        finished();
        return;
    }

    if (confirmation == AskForConfirmation) {
        const auto answer = KMessageBox::questionTwoActions(parentWidgetOrView(),
                                                            xi18nc("@info", "Do you really want to delete the copy of the key stored on this computer?"),
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

    const auto cmd = QByteArray{"DELETE_KEY --force "} + subkey.keyGrip();
    ReaderStatus::mutableInstance()->startSimpleTransaction(card, cmd, q, [this](const GpgME::Error &err) {
        deleteSecretKeyLocallyFinished(err);
    });
}

void KeyToCardCommand::Private::deleteSecretKeyLocallyFinished(const GpgME::Error &err)
{
    ReaderStatus::mutableInstance()->updateStatus();
    if (err) {
        error(xi18nc("@info",
                     "<para>Failed to delete the copy of the key stored on this computer:</para><para><message>%1</message></para>",
                     Formatting::errorAsString(err)));
    } else if (!err.isCanceled()) {
        success(i18nc("@info", "Successfully deleted the copy of the key stored on this computer."));
    }
    finished();
}

KeyToCardCommand::KeyToCardCommand(const GpgME::Subkey &subkey)
    : CardCommand(new Private(this, subkey))
{
}

KeyToCardCommand::KeyToCardCommand(const std::string &cardSlot, const std::string &serialNumber, const std::string &appName, QWidget *parent)
    : CardCommand(new Private(this, cardSlot, serialNumber, appName, parent))
{
}

KeyToCardCommand::~KeyToCardCommand()
{
    qCDebug(KLEOPATRA_LOG) << "KeyToCardCommand::~KeyToCardCommand()";
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
}

// static
std::vector<std::shared_ptr<Card>> KeyToCardCommand::getSuitableCards(const GpgME::Subkey &subkey)
{
    std::vector<std::shared_ptr<Card>> suitableCards;
    if (subkey.isNull() || subkey.parent().protocol() != GpgME::OpenPGP) {
        return suitableCards;
    }
    const auto keyAlgo = subkey.algoName();
    Kleo::copy_if(ReaderStatus::instance()->getCards(), std::back_inserter(suitableCards), [keyAlgo](const auto &card) {
        return cardSupportsKeyAlgorithm(card, keyAlgo);
    });
    return suitableCards;
}

void KeyToCardCommand::Private::keyToCardDone(const GpgME::Error &err)
{
    if (!err && !err.isCanceled()) {
        updateConnection = connect(ReaderStatus::instance(), &ReaderStatus::updateFinished, q, [this]() {
            updateDone();
        });
        ReaderStatus::mutableInstance()->updateCard(serialNumber(), appName);
        return;
    }
    if (err) {
        error(xi18nc("@info", "<para>Copying the key to the card failed:</para><para><message>%1</message></para>", Formatting::errorAsString(err)));
    }
    finished();
}

void KeyToCardCommand::Private::keyToPIVCardDone(const GpgME::Error &err)
{
    qCDebug(KLEOPATRA_LOG) << q << __func__ << Formatting::errorAsString(err) << "(" << err.code() << ")";
#ifdef GPG_ERROR_HAS_NO_AUTH
    // gpgme 1.13 reports "BAD PIN" instead of "NO AUTH"
    if (err.code() == GPG_ERR_NO_AUTH || err.code() == GPG_ERR_BAD_PIN) {
        authenticate();
        return;
    }
#endif
    keyToCardDone(err);
}

void KeyToCardCommand::doStart()
{
    qCDebug(KLEOPATRA_LOG) << "KeyToCardCommand::doStart()";

    d->start();
}

void KeyToCardCommand::doCancel()
{
}

#undef q_func
#undef d_func

#include "moc_keytocardcommand.cpp"
