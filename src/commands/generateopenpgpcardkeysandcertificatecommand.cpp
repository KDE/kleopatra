/*
    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2017 Bundesamt für Sicherheit in der Informationstechnik
    SPDX-FileContributor: Intevation GmbH
    SPDX-FileCopyrightText: 2024 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include <config-kleopatra.h>

#include "generateopenpgpcardkeysandcertificatecommand.h"

#include "cardcommand_p.h"

#include <dialogs/gencardkeydialog.h>
#include <smartcard/algorithminfo.h>
#include <smartcard/openpgpcard.h>
#include <smartcard/readerstatus.h>
#include <smartcard/utils.h>
#include <utils/qt-cxx20-compat.h>

#include <Libkleo/Formatting>

#include <KLocalizedString>

#include <QGpgME/DataProvider>
#include <QGpgME/Debug>

#include <QFileDialog>
#include <QFileInfo>
#include <QLabel>
#include <QProgressDialog>
#include <QThread>

#include <gpgme++/context.h>
#include <gpgme++/data.h>
#include <gpgme++/error.h>
#include <gpgme++/gpggencardkeyinteractor.h>

#include "kleopatra_debug.h"

using namespace Kleo;
using namespace Kleo::Commands;
using namespace Kleo::SmartCard;
using namespace GpgME;

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

class GenerateOpenPGPCardKeysAndCertificateCommand::Private : public CardCommand::Private
{
    friend class ::Kleo::Commands::GenerateOpenPGPCardKeysAndCertificateCommand;
    GenerateOpenPGPCardKeysAndCertificateCommand *q_func() const
    {
        return static_cast<GenerateOpenPGPCardKeysAndCertificateCommand *>(q);
    }

public:
    explicit Private(GenerateOpenPGPCardKeysAndCertificateCommand *qq, const std::string &serialNumber, QWidget *p);

    void init();

private:
    void slotDialogAccepted();
    void slotDialogRejected();
    void slotResult(const Error &err, const std::string &backup);

private:
    void generateKey();
    void start();

private:
    GenCardKeyDialog::KeyParams keyParameters;
    QPointer<GenCardKeyDialog> dialog;
};

GenerateOpenPGPCardKeysAndCertificateCommand::Private *GenerateOpenPGPCardKeysAndCertificateCommand::d_func()
{
    return static_cast<Private *>(d.get());
}
const GenerateOpenPGPCardKeysAndCertificateCommand::Private *GenerateOpenPGPCardKeysAndCertificateCommand::d_func() const
{
    return static_cast<const Private *>(d.get());
}

#define d d_func()
#define q q_func()

GenerateOpenPGPCardKeysAndCertificateCommand::Private::Private(GenerateOpenPGPCardKeysAndCertificateCommand *qq, const std::string &serialNumber, QWidget *p)
    : CardCommand::Private(qq, serialNumber, p)
{
}

void GenerateOpenPGPCardKeysAndCertificateCommand::Private::init()
{
}

void GenerateOpenPGPCardKeysAndCertificateCommand::Private::slotDialogAccepted()
{
    keyParameters = dialog->getKeyParams();
    generateKey();
}

void GenerateOpenPGPCardKeysAndCertificateCommand::Private::slotDialogRejected()
{
    finished();
}

void GenerateOpenPGPCardKeysAndCertificateCommand::Private::slotResult(const GpgME::Error &err, const std::string &backup)
{
    qCDebug(KLEOPATRA_LOG).nospace() << q << "::Private::" << __func__ << err;

    if (err) {
        error(i18nc("@info", "Failed to generate new card keys and a certificate: %1", Formatting::errorAsString(err)));
        finished();
        return;
    }
    if (err.isCanceled()) {
        canceled();
        return;
    }
    if (!backup.empty()) {
        const auto bkpFile = QString::fromStdString(backup);
        QFileInfo fi(bkpFile);
        const auto target = QFileDialog::getSaveFileName(parentWidgetOrView(),
                                                         i18n("Save backup of encryption key"),
                                                         fi.fileName(),
                                                         QStringLiteral("%1 (*.gpg)").arg(i18n("Backup Key")));
        if (!target.isEmpty() && !QFile::copy(bkpFile, target)) {
            error(i18nc("@info", "Failed to move backup. The backup key is still stored under: %1", bkpFile));
        } else if (!target.isEmpty()) {
            QFile::remove(bkpFile);
        }
    }

    success(i18nc("@info", "Successfully generated new card keys and a certificate for this card."), i18nc("@title", "Success"));
    ReaderStatus::mutableInstance()->updateStatus();
    finished();
}

void GenerateOpenPGPCardKeysAndCertificateCommand::Private::generateKey()
{
    qCDebug(KLEOPATRA_LOG).nospace() << q << "::Private::" << __func__;

    const GpgME::Error err = ReaderStatus::switchCardAndApp(serialNumber(), OpenPGPCard::AppName);
    if (err) {
        finished();
        return;
    }

    auto progress = new QProgressDialog(parentWidgetOrView(), Qt::CustomizeWindowHint | Qt::WindowTitleHint | Qt::Dialog);
    progress->setAttribute(Qt::WA_DeleteOnClose);
    progress->setAutoClose(true);
    progress->setMinimumDuration(0);
    progress->setMaximum(0);
    progress->setMinimum(0);
    progress->setModal(true);
    progress->setCancelButton(nullptr);
    progress->setWindowTitle(i18nc("@title:window", "Generating Keys"));
    progress->setLabelText(i18nc("@label:textbox", "This may take several minutes..."));
    auto workerThread = new GenKeyThread(keyParameters, serialNumber());
    connect(workerThread, &QThread::finished, q, [this, workerThread, progress] {
        progress->accept();
        slotResult(workerThread->error(), workerThread->bkpFile());
        delete workerThread;
    });
    workerThread->start();
    progress->exec();
}

void GenerateOpenPGPCardKeysAndCertificateCommand::Private::start()
{
    const auto pgpCard = ReaderStatus::instance()->getCard<OpenPGPCard>(serialNumber());
    if (!pgpCard) {
        error(i18n("Failed to find the OpenPGP card with the serial number: %1", QString::fromStdString(serialNumber())));
        finished();
        return;
    }

    const bool cardIsEmpty = (pgpCard->keyFingerprint(OpenPGPCard::pgpSigKeyRef()).empty() //
                              && pgpCard->keyFingerprint(OpenPGPCard::pgpEncKeyRef()).empty() //
                              && pgpCard->keyFingerprint(OpenPGPCard::pgpAuthKeyRef()).empty());
    if (!cardIsEmpty) {
        const auto ret = KMessageBox::warningContinueCancel(parentWidgetOrView(),
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
            finished();
            return;
        }
    }

    dialog = new GenCardKeyDialog(GenCardKeyDialog::AllKeyAttributes, parentWidgetOrView());
    dialog->setAttribute(Qt::WA_DeleteOnClose);

    connect(dialog, &QDialog::accepted, q, [this]() {
        slotDialogAccepted();
    });
    connect(dialog, &QDialog::rejected, q, [this]() {
        slotDialogRejected();
    });
    const auto allowedAlgos = getAllowedAlgorithms(pgpCard->supportedAlgorithms());
    if (allowedAlgos.empty()) {
        error(i18nc("@info", "You cannot generate keys on this smart card because it doesn't support any of the compliant algorithms."));
        finished();
        return;
    }
    dialog->setSupportedAlgorithms(allowedAlgos, getPreferredAlgorithm(allowedAlgos));
    dialog->show();
}

GenerateOpenPGPCardKeysAndCertificateCommand::GenerateOpenPGPCardKeysAndCertificateCommand(const std::string &serialNumber, QWidget *p)
    : CardCommand(new Private(this, serialNumber, p))
{
    d->init();
}

GenerateOpenPGPCardKeysAndCertificateCommand::~GenerateOpenPGPCardKeysAndCertificateCommand()
{
    qCDebug(KLEOPATRA_LOG).nospace() << this << "::" << __func__;
}

void GenerateOpenPGPCardKeysAndCertificateCommand::doStart()
{
    qCDebug(KLEOPATRA_LOG).nospace() << this << "::" << __func__;

    d->start();
}

void GenerateOpenPGPCardKeysAndCertificateCommand::doCancel()
{
}

#undef d
#undef q

#include "generateopenpgpcardkeysandcertificatecommand.moc"

#include "moc_generateopenpgpcardkeysandcertificatecommand.cpp"
