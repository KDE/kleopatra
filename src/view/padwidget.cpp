/* -*- mode: c++; c-basic-offset:4 -*-
    padwidget.cpp

    This file is part of Kleopatra, the KDE keymanager
    Copyright (c) 2018 Intevation GmbH

    Kleopatra is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    Kleopatra is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
    General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA

    In addition, as a special exception, the copyright holders give
    permission to link the code of this program with any edition of
    the Qt library by Trolltech AS, Norway (or with modified versions
    of Qt that use the same license as Qt), and distribute linked
    combinations including the two.  You must obey the GNU General
    Public License in all respects for all of the code used other than
    Qt.  If you modify this file, you may extend this exception to
    your version of the file, but you are not obligated to do so.  If
    you do not wish to do so, delete this exception statement from
    your version.
*/
#include "padwidget.h"

#include "kleopatra_debug.h"

#include <Libkleo/Exception>
#include <Libkleo/Classify>
#include <Libkleo/KeyCache>

#include "crypto/gui/signencryptwidget.h"
#include "crypto/gui/resultitemwidget.h"

#include "crypto/signencrypttask.h"
#include "crypto/decryptverifytask.h"
#include "utils/gnupg-helper.h"
#include "utils/input.h"
#include "utils/output.h"

#include "commands/importcertificatefromdatacommand.h"

#include <gpgme++/data.h>
#include <gpgme++/decryptionresult.h>

#include <QGpgME/DataProvider>

#include <QButtonGroup>
#include <QFontDatabase>
#include <QFontMetrics>
#include <QLabel>
#include <QProgressBar>
#include <QPushButton>
#include <QRadioButton>
#include <QTabWidget>
#include <QTextEdit>
#include <QVBoxLayout>

#include <KLocalizedString>
#include <KColorScheme>
#include <KMessageBox>

#include <KSharedConfig>
#include <KConfigGroup>

using namespace Kleo;
using namespace Kleo::Crypto;
using namespace Kleo::Crypto::Gui;

static GpgME::Protocol getProtocol(const std::shared_ptr<const Kleo::Crypto::Task::Result> &result)
{
    const auto dvResult = dynamic_cast<const Kleo::Crypto::DecryptVerifyResult*>(result.get());
    if (dvResult) {
        for (const auto &key: KeyCache::instance()->findRecipients(dvResult->decryptionResult())) {
            return key.protocol();
        }
        for (const auto &key: KeyCache::instance()->findSigners(dvResult->verificationResult())) {
            return key.protocol();
        }
    }
    return GpgME::UnknownProtocol;
}

class PadWidget::Private
{
public:
    Private(PadWidget *qq):
        q(qq),
        mEdit(new QTextEdit),
        mCryptBtn(new QPushButton(QIcon::fromTheme(QStringLiteral("document-edit-sign-encrypt")), i18n("Sign / Encrypt Notepad"))),
        mDecryptBtn(new QPushButton(QIcon::fromTheme(QStringLiteral("document-edit-decrypt-verify")), i18n("Decrypt / Verify Notepad"))),
        mRevertBtn(new QPushButton(QIcon::fromTheme(QStringLiteral("edit-undo")), i18n("Revert"))),
        mAdditionalInfoLabel(new QLabel),
        mSigEncWidget(new SignEncryptWidget(nullptr, true)),
        mProgressBar(new QProgressBar),
        mProgressLabel(new QLabel),
        mLastResultWidget(nullptr),
        mPGPRB(nullptr),
        mCMSRB(nullptr),
        mImportProto(GpgME::UnknownProtocol)
    {
        auto vLay = new QVBoxLayout(q);

        auto btnLay = new QHBoxLayout;
        vLay->addLayout(btnLay);
        btnLay->addWidget(mCryptBtn);
        btnLay->addWidget(mDecryptBtn);
        btnLay->addWidget(mRevertBtn);

        mRevertBtn->setVisible(false);

        btnLay->addWidget(mAdditionalInfoLabel);

        btnLay->addStretch(-1);

        mProgressBar->setRange(0, 0);
        mProgressBar->setVisible(false);
        mProgressLabel->setVisible(false);
        auto progLay = new QHBoxLayout;

        progLay->addWidget(mProgressLabel);
        progLay->addWidget(mProgressBar);

        mStatusLay = new QVBoxLayout;
        mStatusLay->addLayout(progLay);
        vLay->addLayout(mStatusLay, 0);

        auto tabWidget = new QTabWidget;
        vLay->addWidget(tabWidget, 1);

        tabWidget->addTab(mEdit, QIcon::fromTheme(QStringLiteral("edittext")), i18n("Notepad"));

        // The recipients area
        auto recipientsWidget = new QWidget;
        auto recipientsVLay = new QVBoxLayout(recipientsWidget);
        auto protocolSelectionLay = new QHBoxLayout;

        bool pgpOnly = KeyCache::instance()->pgpOnly();
        if (!pgpOnly) {
            recipientsVLay->addLayout(protocolSelectionLay);
        }

        protocolSelectionLay->addWidget(new QLabel(i18n("<h3>Protocol:</h3>")));
        protocolSelectionLay->addStretch(-1);
        // Once S/MIME is supported add radio for S/MIME here.

        recipientsVLay->addWidget(mSigEncWidget);
        tabWidget->addTab(recipientsWidget, QIcon::fromTheme(QStringLiteral("contact-new-symbolic")),
                          i18n("Recipients"));

        mEdit->setPlaceholderText(i18n("Enter a message to encrypt or decrypt..."));

        auto fixedFont = QFont(QStringLiteral("Monospace"));
        fixedFont.setStyleHint(QFont::TypeWriter);
        // This does not work well
        // QFontDatabase::systemFont(QFontDatabase::FixedFont);

        mEdit->setFont(fixedFont);
        mEdit->setMinimumWidth(QFontMetrics(fixedFont).averageCharWidth() * 70);
        mEdit->setAcceptRichText(false);

        if (KeyCache::instance()->pgpOnly()) {
            mSigEncWidget->setProtocol(GpgME::OpenPGP);
        } else {
            auto grp = new QButtonGroup(q);
            auto mPGPRB = new QRadioButton(i18n("OpenPGP"));
            auto mCMSRB = new QRadioButton(i18n("S/MIME"));
            grp->addButton(mPGPRB);
            grp->addButton(mCMSRB);

            KConfigGroup config(KSharedConfig::openConfig(), "Notepad");
            if (config.readEntry("wasCMS", false)) {
                mCMSRB->setChecked(true);
                mSigEncWidget->setProtocol(GpgME::CMS);
            } else {
                mPGPRB->setChecked(true);
                mSigEncWidget->setProtocol(GpgME::OpenPGP);
            }

            protocolSelectionLay->addWidget(mPGPRB);
            protocolSelectionLay->addWidget(mCMSRB);
            connect(mPGPRB, &QRadioButton::toggled, q, [this] (bool value) {
                    if (value) {
                        mSigEncWidget->setProtocol(GpgME::OpenPGP);
                    }
                });
            connect(mCMSRB, &QRadioButton::toggled, q, [this] (bool value) {
                    if (value) {
                        mSigEncWidget->setProtocol(GpgME::CMS);
                    }
                });
        }

        updateCommitButton();

        connect(mEdit, &QTextEdit::textChanged, q, [this] () {
                updateCommitButton();
            });

        connect(mCryptBtn, &QPushButton::clicked, q, [this] () {
                if (mImportProto != GpgME::UnknownProtocol) {
                    doImport();
                } else {
                    doEncryptSign();
                }
            });

        connect(mSigEncWidget, &SignEncryptWidget::operationChanged, q, [this] (const QString &) {
                updateCommitButton();
            });

        connect(mDecryptBtn, &QPushButton::clicked, q, [this] () {
                doDecryptVerify();
            });

        connect(mRevertBtn, &QPushButton::clicked, q, [this] () {
                revert();
            });
    }

    void revert()
    {
        mEdit->setPlainText(QString::fromUtf8(mInputData));
        mRevertBtn->setVisible(false);
    }

    void updateRecipientsFromResult(const Kleo::Crypto::DecryptVerifyResult &result)
    {
        const auto decResult = result.decryptionResult();

        for (const auto &recipient: decResult.recipients()) {
            if (!recipient.keyID()) {
                continue;
            }

            GpgME::Key key;
            if (strlen(recipient.keyID()) < 16) {
                key = KeyCache::instance()->findByShortKeyID(recipient.keyID());
            } else {
                key = KeyCache::instance()->findByKeyIDOrFingerprint(recipient.keyID());
            }

            if (key.isNull()) {
                std::vector<std::string> subids;
                subids.push_back(std::string(recipient.keyID()));
                for (const auto &subkey: KeyCache::instance()->findSubkeysByKeyID(subids)) {
                    key = subkey.parent();
                    break;
                }
            }

            if (key.isNull()) {
                qCDebug(KLEOPATRA_LOG) << "Unknown key" << recipient.keyID();
                mSigEncWidget->addUnknownRecipient(recipient.keyID());
                continue;
            }

            bool keyFound = false;
            for (const auto &existingKey: mSigEncWidget->recipients()) {
                if (existingKey.primaryFingerprint() && key.primaryFingerprint() &&
                    !strcmp (existingKey.primaryFingerprint(), key.primaryFingerprint())) {
                    keyFound = true;
                    break;
                }
            }
            if (!keyFound) {
                mSigEncWidget->addRecipient(key);
            }
        }
    }

    void cryptDone(const std::shared_ptr<const Kleo::Crypto::Task::Result> &result)
    {
        updateCommitButton();
        mDecryptBtn->setEnabled(true);
        mProgressBar->setVisible(false);
        mProgressLabel->setVisible(false);

        mLastResultWidget = new ResultItemWidget(result);
        mLastResultWidget->showCloseButton(true);
        mStatusLay->addWidget(mLastResultWidget);

        connect(mLastResultWidget, &ResultItemWidget::closeButtonClicked, q, [this] () {
            removeLastResultItem();
        });

        // Check result protocol
        if (mPGPRB) {
            auto proto = getProtocol(result);
            if (proto == GpgME::UnknownProtocol) {
                proto = mPGPRB->isChecked() ? GpgME::OpenPGP : GpgME::CMS;
            } else if (proto == GpgME::OpenPGP) {
                mPGPRB->setChecked(true);
            } else if (proto == GpgME::CMS) {
                mCMSRB->setChecked(true);
            }

            KConfigGroup config(KSharedConfig::openConfig(), "Notepad");
            config.writeEntry("wasCMS", proto == GpgME::CMS);
        }

        if (result->errorCode()) {
            if (!result->errorString().isEmpty()) {
                KMessageBox::error(q,
                        result->errorString(),
                        i18nc("@title", "Error in crypto action"));
            }
            return;
        }
        mEdit->setPlainText(QString::fromUtf8(mOutputData));
        mOutputData.clear();
        mRevertBtn->setVisible(true);

        const auto decryptVerifyResult = dynamic_cast<const Kleo::Crypto::DecryptVerifyResult*>(result.get());
        if (decryptVerifyResult) {
            updateRecipientsFromResult(*decryptVerifyResult);
        }
    }

    void doDecryptVerify()
    {
        doCryptoCommon();
        mSigEncWidget->clearAddedRecipients();
        mProgressLabel->setText(i18n("Decrypt / Verify") + QStringLiteral("..."));
        auto input = Input::createFromByteArray(&mInputData,  i18n("Notepad"));
        auto output = Output::createFromByteArray(&mOutputData, i18n("Notepad"));

        AbstractDecryptVerifyTask *task;
        auto classification = input->classification();
        if (classification & Class::OpaqueSignature ||
            classification & Class::ClearsignedMessage) {
            auto verifyTask = new VerifyOpaqueTask();
            verifyTask->setInput(input);
            verifyTask->setOutput(output);
            task = verifyTask;
        } else {
            auto decTask = new DecryptVerifyTask();
            decTask->setInput(input);
            decTask->setOutput(output);
            task = decTask;
        }
        try {
            task->autodetectProtocolFromInput();
        } catch (const Kleo::Exception &e) {
            KMessageBox::error(q,
                    e.message(),
                    i18nc("@title", "Error in crypto action"));
            mCryptBtn->setEnabled(true);
            mDecryptBtn->setEnabled(true);
            mProgressBar->setVisible(false);
            mProgressLabel->setVisible(false);
            return;
        }

        connect (task, &Task::result, q, [this, task] (const std::shared_ptr<const Kleo::Crypto::Task::Result> &result) {
                qCDebug(KLEOPATRA_LOG) << "Decrypt / Verify done. Err:" << result->errorCode();
                task->deleteLater();
                cryptDone(result);
            });
        task->start();
    }

    void removeLastResultItem()
    {
        if (mLastResultWidget) {
            mStatusLay->removeWidget(mLastResultWidget);
            delete mLastResultWidget;
            mLastResultWidget = nullptr;
        }
    }

    void doCryptoCommon()
    {
        mCryptBtn->setEnabled(false);
        mDecryptBtn->setEnabled(false);
        mProgressBar->setVisible(true);
        mProgressLabel->setVisible(true);
        mInputData = mEdit->toPlainText().toUtf8();
        removeLastResultItem();
    }

    void doEncryptSign()
    {
        doCryptoCommon();
        mProgressLabel->setText(mSigEncWidget->currentOp() + QStringLiteral("..."));
        auto input = Input::createFromByteArray(&mInputData,  i18n("Notepad"));
        auto output = Output::createFromByteArray(&mOutputData, i18n("Notepad"));

        auto task = new SignEncryptTask();
        task->setInput(input);
        task->setOutput(output);

        const auto sigKey = mSigEncWidget->signKey();

        bool encrypt = mSigEncWidget->encryptSymmetric() || mSigEncWidget->recipients().size();
        bool sign = !sigKey.isNull();

        if (sign) {
            task->setSign(true);
            std::vector<GpgME::Key> signVector;
            signVector.push_back(sigKey);
            task->setSigners(signVector);
        } else {
            task->setSign(false);
        }
        task->setEncrypt(encrypt);
        task->setRecipients(mSigEncWidget->recipients().toStdVector());
        task->setEncryptSymmetric(mSigEncWidget->encryptSymmetric());
        task->setAsciiArmor(true);

        if (sign && !encrypt && sigKey.protocol() == GpgME::OpenPGP) {
            task->setClearsign(true);
        }

        connect (task, &Task::result, q, [this, task] (const std::shared_ptr<const Kleo::Crypto::Task::Result> &result) {
                qCDebug(KLEOPATRA_LOG) << "Encrypt / Sign done. Err:" << result->errorCode();
                task->deleteLater();
                cryptDone(result);
            });
        task->start();
    }

    void doImport()
    {
        doCryptoCommon();
        mProgressLabel->setText(i18n("Importing..."));
        auto cmd = new Kleo::ImportCertificateFromDataCommand(mInputData, mImportProto);
        connect(cmd, &Kleo::ImportCertificatesCommand::finished, q, [this] () {
                mCryptBtn->setEnabled(true);
                mDecryptBtn->setEnabled(true);
                mProgressBar->setVisible(false);
                mProgressLabel->setVisible(false);

                updateCommitButton();
                mRevertBtn->setVisible(true);
                mEdit->setPlainText(QString());
            });
        cmd->start();
    }

    void checkImportProtocol()
    {
        QGpgME::QByteArrayDataProvider dp(mEdit->toPlainText().toUtf8());
        GpgME::Data data(&dp);
        auto type = data.type();
        if (type == GpgME::Data::PGPKey) {
            mImportProto = GpgME::OpenPGP;
        } else if (type == GpgME::Data::X509Cert ||
                   type == GpgME::Data::PKCS12) {
            mImportProto = GpgME::CMS;
        } else {
            mImportProto = GpgME::UnknownProtocol;
        }
    }

    void updateCommitButton()
    {
        mAdditionalInfoLabel->setVisible(false);

        checkImportProtocol();

        if (mImportProto != GpgME::UnknownProtocol) {
            mCryptBtn->setText(i18nc("1 is an operation to apply to the notepad. "
                                     "Like Sign/Encrypt or just Encrypt.", "%1 Notepad",
                                     i18n("Import")));
            mCryptBtn->setDisabled(false);
            return;
        }

        if (!mSigEncWidget->currentOp().isEmpty()) {
            mCryptBtn->setDisabled(false);
            mCryptBtn->setText(i18nc("1 is an operation to apply to the notepad. "
                                     "Like Sign/Encrypt or just Encrypt.", "%1 Notepad",
                                     mSigEncWidget->currentOp()));
        } else {
            mCryptBtn->setText(i18n("Sign / Encrypt Notepad"));
            mCryptBtn->setDisabled(true);
        }

        if (Kleo::gpgComplianceP("de-vs")) {
            bool de_vs = mSigEncWidget->isDeVsAndValid();
            mCryptBtn->setIcon(QIcon::fromTheme(de_vs
                        ? QStringLiteral("security-high")
                        : QStringLiteral("security-medium")));
            mCryptBtn->setStyleSheet(QStringLiteral("background-color: ") + (de_vs
                        ? KColorScheme(QPalette::Active, KColorScheme::View).background(KColorScheme::PositiveBackground).color().name()
                        : KColorScheme(QPalette::Active, KColorScheme::View).background(KColorScheme::NegativeBackground).color().name()));
            mAdditionalInfoLabel->setText(de_vs
                    ? i18nc("VS-NfD-conforming is a German standard for restricted documents for which special restrictions about algorithms apply.  The string states that all cryptographic operations necessary for the communication are compliant with that.",
                        "VS-NfD-compliant communication possible.")
                    : i18nc("VS-NfD-conforming is a German standard for restricted documents for which special restrictions about algorithms apply.  The string states that all cryptographic operations necessary for the communication are compliant with that.",
                        "VS-NfD-compliant communication not possible."));
            mAdditionalInfoLabel->setVisible(true);
        }
    }

private:
    PadWidget *q;
    QTextEdit *mEdit;
    QPushButton *mCryptBtn;
    QPushButton *mDecryptBtn;
    QPushButton *mRevertBtn;
    QLabel *mAdditionalInfoLabel;
    QByteArray mInputData;
    QByteArray mOutputData;
    SignEncryptWidget *mSigEncWidget;
    QProgressBar *mProgressBar;
    QLabel *mProgressLabel;
    QVBoxLayout *mStatusLay;
    ResultItemWidget *mLastResultWidget;
    QList<GpgME::Key> mAutoAddedKeys;
    QRadioButton *mPGPRB;
    QRadioButton *mCMSRB;
    GpgME::Protocol mImportProto;
};

PadWidget::PadWidget(QWidget *parent):
    QWidget(parent),
    d(new Private(this))
{
}
