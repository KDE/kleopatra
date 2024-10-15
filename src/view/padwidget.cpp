/* -*- mode: c++; c-basic-offset:4 -*-
    padwidget.cpp

    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2018 Intevation GmbH

    SPDX-License-Identifier: GPL-2.0-or-later
*/
#include "padwidget.h"

#include "kleopatra_debug.h"

#include <settings.h>

#include <Libkleo/Classify>
#include <Libkleo/Compliance>
#include <Libkleo/Formatting>
#include <Libkleo/KeyCache>
#include <Libkleo/KleoException>
#include <Libkleo/SystemInfo>

#include "crypto/gui/resultitemwidget.h"
#include "crypto/gui/signencryptwidget.h"

#include "crypto/decryptverifytask.h"
#include "crypto/signencrypttask.h"
#include "utils/input.h"
#include "utils/output.h"
#include <Libkleo/GnuPG>

#include "commands/importcertificatefromdatacommand.h"

#include <gpgme++/data.h>
#include <gpgme++/decryptionresult.h>

#include <QGpgME/DataProvider>

#include <QButtonGroup>
#include <QFontDatabase>
#include <QFontMetrics>
#include <QFrame>
#include <QLabel>
#include <QProgressBar>
#include <QPushButton>
#include <QRadioButton>
#include <QSplitter>
#include <QStyle>
#include <QTextEdit>
#include <QVBoxLayout>

#include <KColorScheme>
#include <KConfigGroup>
#include <KLocalizedString>
#include <KMessageBox>
#include <KMessageWidget>
#include <KSharedConfig>

using namespace Kleo;
using namespace Kleo::Crypto;
using namespace Kleo::Crypto::Gui;

static GpgME::Protocol getProtocol(const std::shared_ptr<const Kleo::Crypto::Task::Result> &result)
{
    const auto dvResult = dynamic_cast<const Kleo::Crypto::DecryptVerifyResult *>(result.get());
    if (dvResult) {
        for (const auto &key : KeyCache::instance()->findRecipients(dvResult->decryptionResult())) {
            return key.protocol();
        }
        for (const auto &key : KeyCache::instance()->findSigners(dvResult->verificationResult())) {
            return key.protocol();
        }
    }
    return GpgME::UnknownProtocol;
}

class PadWidget::Private
{
    friend class ::Kleo::PadWidget;

public:
    Private(PadWidget *qq)
        : q(qq)
        , mEdit(new QTextEdit)
        , mCryptBtn(new QPushButton(QIcon::fromTheme(QStringLiteral("document-edit-sign-encrypt")), i18n("Sign / Encrypt Notepad")))
        , mDecryptBtn(new QPushButton(QIcon::fromTheme(QStringLiteral("document-edit-decrypt-verify")), i18n("Decrypt / Verify Notepad")))
        , mImportBtn(new QPushButton(QIcon::fromTheme(QStringLiteral("view-certificate-import")), i18n("Import Notepad")))
        , mRevertBtn(new QPushButton(QIcon::fromTheme(QStringLiteral("edit-undo")), i18n("Revert")))
        , mMessageWidget{new KMessageWidget}
        , mAdditionalInfoLabel(new QLabel)
        , mSigEncWidget(new SignEncryptWidget(nullptr, true))
        , mProgressBar(new QProgressBar)
        , mProgressLabel(new QLabel)
        , mLastResultWidget(nullptr)
        , mPGPRB(nullptr)
        , mCMSRB(nullptr)
        , mImportProto(GpgME::UnknownProtocol)
    {
        auto vLay = new QVBoxLayout(q);
        vLay->setContentsMargins({});
        vLay->setSpacing(0);

        auto btnLay = new QHBoxLayout;
        btnLay->setSpacing(q->style()->pixelMetric(QStyle::PM_LayoutHorizontalSpacing));
        btnLay->setContentsMargins(q->style()->pixelMetric(QStyle::PM_LayoutLeftMargin),
                                   q->style()->pixelMetric(QStyle::PM_LayoutTopMargin),
                                   q->style()->pixelMetric(QStyle::PM_LayoutRightMargin),
                                   q->style()->pixelMetric(QStyle::PM_LayoutBottomMargin));
        vLay->addLayout(btnLay);
        btnLay->addWidget(mCryptBtn);
        btnLay->addWidget(mDecryptBtn);
        btnLay->addWidget(mImportBtn);
        btnLay->addWidget(mRevertBtn);

        auto separator = new QFrame(q);
        separator->setFrameStyle(QFrame::HLine);
        separator->setMaximumHeight(1);
        vLay->addWidget(separator);

        mRevertBtn->setVisible(false);

        btnLay->addWidget(mAdditionalInfoLabel);

        btnLay->addStretch(-1);

        mMessageWidget->setMessageType(KMessageWidget::Warning);
        mMessageWidget->setIcon(q->style()->standardIcon(QStyle::SP_MessageBoxWarning, nullptr, q));
        mMessageWidget->setText(i18n("Signing and encryption is not possible."));
        mMessageWidget->setToolTip(xi18nc("@info %1 is a placeholder for the name of a compliance mode. E.g. NATO RESTRICTED compliant or VS-NfD compliant",
                                          "<para>You cannot use <application>Kleopatra</application> for signing or encryption "
                                          "because the <application>GnuPG</application> system used by <application>Kleopatra</application> is not %1.</para>",
                                          DeVSCompliance::name(true)));
        mMessageWidget->setCloseButtonVisible(false);
        mMessageWidget->setVisible(false);
        vLay->addWidget(mMessageWidget);

        mProgressBar->setRange(0, 0);
        mProgressBar->setVisible(false);
        mProgressLabel->setVisible(false);
        auto progLay = new QHBoxLayout;

        progLay->addWidget(mProgressLabel);
        progLay->addWidget(mProgressBar);

        mStatusLay = new QVBoxLayout;
        mStatusLay->addLayout(progLay);
        vLay->addLayout(mStatusLay, 0);

        auto splitterWidget = new QSplitter;
        splitterWidget->setChildrenCollapsible(false);
        vLay->addWidget(splitterWidget, 1);

        splitterWidget->addWidget(mEdit);

        // The recipients area
        auto recipientsWidget = new QWidget;
        auto recipientsVLay = new QVBoxLayout(recipientsWidget);
        auto protocolSelectionLay = new QHBoxLayout;

        bool pgpOnly = KeyCache::instance()->pgpOnly();
        if (!pgpOnly) {
            recipientsVLay->addLayout(protocolSelectionLay);
        }

        protocolSelectionLay->addWidget(new QLabel(i18nc("@label:textbox", "<h3>Protocol:</h3>")));
        protocolSelectionLay->addStretch(-1);
        // Once S/MIME is supported add radio for S/MIME here.

        recipientsVLay->addWidget(mSigEncWidget);

        mCryptBtn->setSizePolicy(QSizePolicy::Maximum, QSizePolicy::Maximum);
        auto hLay = new QHBoxLayout;
        hLay->addStretch();
        hLay->addWidget(mCryptBtn);
        recipientsVLay->addLayout(hLay);
        splitterWidget->addWidget(recipientsWidget);

        mEdit->setPlaceholderText(i18nc("@info:placeholder", "Enter a message to encrypt or decrypt..."));

        auto fixedFont = QFont(QStringLiteral("Monospace"));
        fixedFont.setStyleHint(QFont::TypeWriter);
        // This does not work well
        // QFontDatabase::systemFont(QFontDatabase::FixedFont);

        mEdit->setFont(fixedFont);
        mEdit->setAcceptRichText(false);
        mEdit->setMinimumWidth(QFontMetrics(fixedFont).averageCharWidth() * 70);

        if (KeyCache::instance()->pgpOnly() || !Settings{}.cmsEnabled()) {
            mSigEncWidget->setProtocol(GpgME::OpenPGP);
        } else {
            auto grp = new QButtonGroup(q);
            auto mPGPRB = new QRadioButton(i18nc("@option:radio", "OpenPGP"));
            auto mCMSRB = new QRadioButton(i18nc("@option:radio", "S/MIME"));
            grp->addButton(mPGPRB);
            grp->addButton(mCMSRB);

            KConfigGroup config(KSharedConfig::openConfig(), QStringLiteral("Notepad"));
            if (config.readEntry("wasCMS", false)) {
                mCMSRB->setChecked(true);
                mSigEncWidget->setProtocol(GpgME::CMS);
            } else {
                mPGPRB->setChecked(true);
                mSigEncWidget->setProtocol(GpgME::OpenPGP);
            }

            protocolSelectionLay->addWidget(mPGPRB);
            protocolSelectionLay->addWidget(mCMSRB);
            connect(mPGPRB, &QRadioButton::toggled, q, [this](bool value) {
                if (value) {
                    mSigEncWidget->setProtocol(GpgME::OpenPGP);
                }
            });
            connect(mCMSRB, &QRadioButton::toggled, q, [this](bool value) {
                if (value) {
                    mSigEncWidget->setProtocol(GpgME::CMS);
                }
            });
        }

        updateButtons();

        connect(mEdit, &QTextEdit::textChanged, q, [this]() {
            updateButtons();
        });

        connect(mCryptBtn, &QPushButton::clicked, q, [this]() {
            doEncryptSign();
        });

        connect(mSigEncWidget, &SignEncryptWidget::operationChanged, q, [this]() {
            updateButtons();
        });

        connect(mDecryptBtn, &QPushButton::clicked, q, [this]() {
            doDecryptVerify();
        });

        connect(mImportBtn, &QPushButton::clicked, q, [this]() {
            doImport();
        });

        connect(mRevertBtn, &QPushButton::clicked, q, [this]() {
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

        for (const auto &recipient : decResult.recipients()) {
            if (!recipient.keyID()) {
                continue;
            }

            GpgME::Key key = KeyCache::instance()->findByKeyIDOrFingerprint(recipient.keyID());

            if (key.isNull()) {
                std::vector<std::string> subids;
                subids.push_back(std::string(recipient.keyID()));
                for (const auto &subkey : KeyCache::instance()->findSubkeysByKeyID(subids)) {
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
            for (const auto &existingKey : mSigEncWidget->recipients()) {
                if (existingKey.primaryFingerprint() && key.primaryFingerprint() && !strcmp(existingKey.primaryFingerprint(), key.primaryFingerprint())) {
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
        updateButtons();
        mProgressBar->setVisible(false);
        mProgressLabel->setVisible(false);

        if (!result->error().isCanceled()) {
            mLastResultWidget = new ResultItemWidget(result);
            mLastResultWidget->showCloseButton(true);
            mStatusLay->addWidget(mLastResultWidget);

            connect(mLastResultWidget, &ResultItemWidget::closeButtonClicked, q, [this]() {
                removeLastResultItem();
            });
        }

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

            KConfigGroup config(KSharedConfig::openConfig(), QStringLiteral("Notepad"));
            config.writeEntry("wasCMS", proto == GpgME::CMS);
        }

        if (result->error()) {
            if (!result->errorString().isEmpty()) {
                KMessageBox::error(q, result->errorString());
            }
        } else if (!result->error().isCanceled()) {
            mEdit->setPlainText(QString::fromUtf8(mOutputData));
            mOutputData.clear();
            mRevertBtn->setVisible(true);

            const auto decryptVerifyResult = dynamic_cast<const Kleo::Crypto::DecryptVerifyResult *>(result.get());
            if (decryptVerifyResult) {
                updateRecipientsFromResult(*decryptVerifyResult);
            }
        }
    }

    void doDecryptVerify()
    {
        doCryptoCommon();
        mSigEncWidget->clearAddedRecipients();
        mProgressLabel->setText(i18n("Decrypt / Verify") + QStringLiteral("..."));
        auto input = Input::createFromByteArray(&mInputData, i18n("Notepad"));
        auto output = Output::createFromByteArray(&mOutputData, i18n("Notepad"));

        AbstractDecryptVerifyTask *task;
        auto classification = input->classification();
        if (classification & Class::OpaqueSignature || classification & Class::ClearsignedMessage) {
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
            KMessageBox::error(q, e.message());
            updateButtons();
            mProgressBar->setVisible(false);
            mProgressLabel->setVisible(false);
            return;
        }
        task->setIsNotepad(true);

        connect(task, &Task::result, q, [this, task](const std::shared_ptr<const Kleo::Crypto::Task::Result> &result) {
            qCDebug(KLEOPATRA_LOG) << "Decrypt / Verify done. Err:" << result->error().code();
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
        mImportBtn->setEnabled(false);
        mProgressBar->setVisible(true);
        mProgressLabel->setVisible(true);
        mInputData = mEdit->toPlainText().toUtf8();
        removeLastResultItem();
    }

    void doEncryptSign()
    {
        if (DeVSCompliance::isActive() && !DeVSCompliance::isCompliant()) {
            KMessageBox::error(q->topLevelWidget(),
                               xi18nc("@info %1 is a placeholder for the name of a compliance mode. E.g. NATO RESTRICTED compliant or VS-NfD compliant",
                                      "<para>Sorry! You cannot use <application>Kleopatra</application> for signing or encryption "
                                      "because the <application>GnuPG</application> system used by <application>Kleopatra</application> is not %1.</para>",
                                      DeVSCompliance::name(true)));
            return;
        }

        mSigEncWidget->saveOwnKeys();
        doCryptoCommon();
        switch (mSigEncWidget->currentOp()) {
        case SignEncryptWidget::Sign:
            mProgressLabel->setText(i18nc("@info:progress", "Signing notepad..."));
            break;
        case SignEncryptWidget::Encrypt:
            mProgressLabel->setText(i18nc("@info:progress", "Encrypting notepad..."));
            break;
        case SignEncryptWidget::SignAndEncrypt:
            mProgressLabel->setText(i18nc("@info:progress", "Signing and encrypting notepad..."));
            break;
        default:;
        };
        auto input = Input::createFromByteArray(&mInputData, i18n("Notepad"));
        auto output = Output::createFromByteArray(&mOutputData, i18n("Notepad"));

        auto task = new SignEncryptTask();
        task->setInput(input);
        task->setOutput(output);
        task->setIsNotepad(true);

        const auto sigKey = mSigEncWidget->signUserId().parent();

        const std::vector<GpgME::Key> recipients = mSigEncWidget->recipients();
        const bool encrypt = mSigEncWidget->encryptSymmetric() || !recipients.empty();
        const bool sign = !sigKey.isNull();

        if (sign) {
            task->setSign(true);
            std::vector<GpgME::Key> signVector;
            signVector.push_back(sigKey);
            task->setSigners(signVector);
        } else {
            task->setSign(false);
        }
        task->setEncrypt(encrypt);
        task->setRecipients(recipients);
        task->setEncryptSymmetric(mSigEncWidget->encryptSymmetric());
        task->setAsciiArmor(true);

        if (sign && !encrypt && sigKey.protocol() == GpgME::OpenPGP) {
            task->setClearsign(true);
        }

        connect(task, &Task::result, q, [this, task](const std::shared_ptr<const Kleo::Crypto::Task::Result> &result) {
            qCDebug(KLEOPATRA_LOG) << "Encrypt / Sign done. Err:" << result->error().code();
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
        connect(cmd, &Kleo::ImportCertificatesCommand::finished, q, [this]() {
            updateButtons();
            mProgressBar->setVisible(false);
            mProgressLabel->setVisible(false);

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
        } else if (type == GpgME::Data::X509Cert || type == GpgME::Data::PKCS12) {
            mImportProto = GpgME::CMS;
        } else {
            mImportProto = GpgME::UnknownProtocol;
        }
    }

    void updateButtons()
    {
        mAdditionalInfoLabel->setVisible(false);

        mDecryptBtn->setEnabled(mEdit->document() && !mEdit->document()->isEmpty());

        checkImportProtocol();
        mImportBtn->setEnabled(mImportProto != GpgME::UnknownProtocol);

        mCryptBtn->setEnabled(mSigEncWidget->currentOp() != SignEncryptWidget::NoOperation);
        switch (mSigEncWidget->currentOp()) {
        case SignEncryptWidget::Sign:
            mCryptBtn->setText(i18nc("@action:button", "Sign Notepad"));
            break;
        case SignEncryptWidget::Encrypt:
            mCryptBtn->setText(i18nc("@action:button", "Encrypt Notepad"));
            break;
        case SignEncryptWidget::SignAndEncrypt:
        default:
            mCryptBtn->setText(i18nc("@action:button", "Sign / Encrypt Notepad"));
        };
        if (!mSigEncWidget->isComplete()) {
            mCryptBtn->setEnabled(false);
        }

        if (DeVSCompliance::isActive()) {
            const bool de_vs = DeVSCompliance::isCompliant() && mSigEncWidget->isDeVsAndValid();
            DeVSCompliance::decorate(mCryptBtn, de_vs);
            mAdditionalInfoLabel->setText(DeVSCompliance::name(de_vs));
            mAdditionalInfoLabel->setVisible(true);
            if (!DeVSCompliance::isCompliant()) {
                mCryptBtn->setEnabled(false);
            }
            mMessageWidget->setVisible(!DeVSCompliance::isCompliant());
        }
    }

private:
    PadWidget *const q;
    QTextEdit *mEdit;
    QPushButton *mCryptBtn;
    QPushButton *mDecryptBtn;
    QPushButton *mImportBtn;
    QPushButton *mRevertBtn;
    KMessageWidget *mMessageWidget;
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

PadWidget::PadWidget(QWidget *parent)
    : QWidget(parent)
    , d(new Private(this))
{
}

void PadWidget::focusFirstChild(Qt::FocusReason reason)
{
    d->mEdit->setFocus(reason);
}

#include "moc_padwidget.cpp"
