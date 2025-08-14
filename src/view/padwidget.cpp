/*
    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2018 Intevation GmbH

    SPDX-License-Identifier: GPL-2.0-or-later
*/
#include "padwidget.h"

#include "kleopatra_debug.h"

#include <settings.h>

#include <Libkleo/ApplicationPaletteWatcher>
#include <Libkleo/Classify>
#include <Libkleo/Compliance>
#include <Libkleo/Formatting>
#include <Libkleo/GnuPG>
#include <Libkleo/KeyCache>
#include <Libkleo/KleoException>
#include <Libkleo/SystemInfo>

#include "commands/importcertificatefromdatacommand.h"
#include "crypto/decryptverifytask.h"
#include "crypto/gui/resultitemwidget.h"
#include "crypto/gui/signencryptwidget.h"
#include "crypto/signencrypttask.h"
#include "utils/gui-helper.h"
#include "utils/input.h"
#include "utils/output.h"

#include <gpgme++/data.h>
#include <gpgme++/decryptionresult.h>

#include <QGpgME/DataProvider>

#include <QAccessible>
#include <QButtonGroup>
#include <QFontMetrics>
#include <QFrame>
#include <QLabel>
#include <QPointer>
#include <QProgressBar>
#include <QPushButton>
#include <QRadioButton>
#include <QSplitter>
#include <QStyle>
#include <QTextEdit>
#include <QVBoxLayout>

#include <KAdjustingScrollArea>
#include <KConfigGroup>
#include <KLocalizedString>
#include <KMessageBox>
#include <KMessageWidget>
#include <KSeparator>
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
    enum Operation {
        NoOperation,
        SignEncrypt,
        DecryptVerify,
        Import,
    };

    explicit Private(PadWidget *qq)
        : q(qq)
        , mEdit(new QTextEdit)
        , mCryptBtn(new QPushButton(QIcon::fromTheme(QStringLiteral("document-edit-sign-encrypt")), i18n("Sign / Encrypt Notepad")))
        , mDecryptBtn(new QPushButton(QIcon::fromTheme(QStringLiteral("document-edit-decrypt-verify")), i18n("Decrypt / Verify Notepad")))
        , mImportBtn(new QPushButton(QIcon::fromTheme(QStringLiteral("view-certificate-import")), i18n("Import Notepad")))
        , mRevertBtn(new QPushButton(QIcon::fromTheme(QStringLiteral("edit-undo")), i18n("Revert")))
        , mMessageWidget{new KMessageWidget}
        , mAdditionalInfoLabel(new QLabel)
        , mSigEncWidget(nullptr)
        , mProgressBar(new QProgressBar)
        , mProgressLabel(new QLabel)
        , mLastResultWidget(nullptr)
        , mImportProto(GpgME::UnknownProtocol)
    {
        auto vLay = new QVBoxLayout(q);
        vLay->setContentsMargins({});
        vLay->setSpacing(0);

        mMessageWidget->setMessageType(KMessageWidget::Warning);
        mMessageWidget->setIcon(q->style()->standardIcon(QStyle::SP_MessageBoxWarning, nullptr, q));
        mMessageWidget->setText(i18n("Signing and encryption is not possible."));
        mMessageWidget->setToolTip(xi18nc("@info %1 is a placeholder for the name of a compliance mode. E.g. NATO RESTRICTED compliant or VS-NfD compliant",
                                          "<para>You cannot use <application>Kleopatra</application> for signing or encryption "
                                          "because the <application>GnuPG</application> system used by <application>Kleopatra</application> is not %1.</para>",
                                          DeVSCompliance::name(true)));
        mMessageWidget->setCloseButtonVisible(false);
        mMessageWidget->setVisible(false);
        mMessageWidget->setPosition(KMessageWidget::Position::Header);
        vLay->addWidget(mMessageWidget);

        mRevertBtn->setVisible(false);

        mProgressBar->setRange(0, 0);
        mProgressBar->setVisible(false);
        mProgressLabel->setVisible(false);
        mProgressLabel->setFocusPolicy(Qt::TabFocus);
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
        splitterWidget->setStretchFactor(0, 1);

        // The recipients area
        auto scrollArea = new KAdjustingScrollArea;
        scrollArea->setFocusPolicy(Qt::NoFocus);
        auto recipientsWidget = new QWidget;
        scrollArea->setWidget(recipientsWidget);
        auto recipientsVLay = new QVBoxLayout(recipientsWidget);

        mSigEncWidget = new SignEncryptWidget(nullptr, true);
        recipientsVLay->addWidget(mSigEncWidget);
        splitterWidget->addWidget(scrollArea);

        mCryptBtn->setSizePolicy(QSizePolicy::Maximum, QSizePolicy::Maximum);

        auto btnLay = new QHBoxLayout;
        btnLay->setSpacing(q->style()->pixelMetric(QStyle::PM_LayoutHorizontalSpacing));
        btnLay->setContentsMargins(q->style()->pixelMetric(QStyle::PM_LayoutLeftMargin),
                                   q->style()->pixelMetric(QStyle::PM_LayoutTopMargin),
                                   q->style()->pixelMetric(QStyle::PM_LayoutRightMargin),
                                   q->style()->pixelMetric(QStyle::PM_LayoutBottomMargin));
        vLay->addLayout(btnLay);
        btnLay->addWidget(mDecryptBtn);
        btnLay->addWidget(mImportBtn);
        btnLay->addWidget(mRevertBtn);
        btnLay->addStretch();
        btnLay->addWidget(mAdditionalInfoLabel);
        btnLay->addWidget(mCryptBtn);

        resetAccessibleNameAndDescription();
        mEdit->setPlaceholderText(i18nc("@info:placeholder", "Enter a message to encrypt or decrypt..."));

        auto fixedFont = QFont(QStringLiteral("Monospace"));
        fixedFont.setStyleHint(QFont::TypeWriter);

        mEdit->setFont(fixedFont);
        mEdit->setAcceptRichText(false);
        mEdit->setTabChangesFocus(true);
        mEdit->setMinimumWidth(QFontMetrics(fixedFont).averageCharWidth() * 70);

        updateButtons();

        connect(mEdit, &QTextEdit::textChanged, q, [this]() {
            onTextChanged();
        });
        connect(&appPaletteWatcher, &ApplicationPaletteWatcher::paletteChanged, q, [this]() {
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

    void resetAccessibleNameAndDescription()
    {
        mEdit->setAccessibleName(i18nc("@label:textbox for assistive tools", "Text to process"));
        mEdit->setAccessibleDescription(i18nc("@info for assistive tools",
                                              "Either enter a text you want to sign or encrypt, "
                                              "or an encrypted or signed text you want to decrypt or verify. "
                                              "You can also enter certificates in text form to import them."));
    }

    void setText(const QString &text)
    {
        mSettingText = true;
        mEdit->setPlainText(text);
        mSettingText = false;
    }

    void saveFocusWidget()
    {
        mFocusWidget = q->focusWidget();
    }

    void restoreFocusWidget()
    {
        if (mFocusWidget) {
            mFocusWidget->setFocus();
            mFocusWidget.clear();
        }
    }

    /* Show progress widgets and move focus to progress label to trigger screen readers. */
    void startProgress(const QString &text)
    {
        mProgressBar->setVisible(true);
        mProgressLabel->setText(text);
        mProgressLabel->setVisible(true);
        mProgressLabel->setFocus();
    }

    void stopProgress()
    {
        mProgressBar->setVisible(false);
        mProgressLabel->setVisible(false);
    }

    void onTextChanged()
    {
        if (!mSettingText) {
            // the user changed the text
            mLastOperation = NoOperation;
            resetAccessibleNameAndDescription();
        }
        updateButtons();
    }

    void revert()
    {
        mLastOperation = NoOperation;
        resetAccessibleNameAndDescription();
        setText(QString::fromUtf8(mInputData));
        mRevertBtn->setVisible(false);
        removeLastResultItem();
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
        restoreFocusWidget();
        stopProgress();

        if (!result->error().isCanceled()) {
            mLastResultWidget = new ResultItemWidget(result);
            mLastResultWidget->showCloseButton(true);
            mStatusLay->addWidget(mLastResultWidget);
            mLastResultWidget->setFocus(); // trigger screen readers

            connect(mLastResultWidget, &ResultItemWidget::closeButtonClicked, q, [this]() {
                removeLastResultItem();
            });
        }

        const auto protocol = getProtocol(result);
        if (protocol != GpgME::Protocol::UnknownProtocol) {
            mSigEncWidget->setProtocol(protocol);
        }

        if (result->error()) {
            if (!result->errorString().isEmpty()) {
                KMessageBox::error(q, result->errorString());
            }
        } else if (!result->error().isCanceled()) {
            const auto decryptVerifyResult = dynamic_cast<const Kleo::Crypto::DecryptVerifyResult *>(result.get());
            if (decryptVerifyResult) {
                updateRecipientsFromResult(*decryptVerifyResult);
            }

            switch (mLastOperation) {
            case SignEncrypt: {
                switch (mSigEncWidget->currentOp()) {
                case SignEncryptWidget::Sign:
                    mEdit->setAccessibleName(i18nc("@label:textbox for assistive tools", "Signed text"));
                    mEdit->setAccessibleDescription(i18nc("@info for assistive tools", "This is the result of the sign operation."));
                    break;
                case SignEncryptWidget::Encrypt:
                    mEdit->setAccessibleName(i18nc("@label:textbox for assistive tools", "Encrypted text"));
                    mEdit->setAccessibleDescription(i18nc("@info for assistive tools", "This is the result of the encryption."));
                    break;
                case SignEncryptWidget::SignAndEncrypt:
                    mEdit->setAccessibleName(i18nc("@label:textbox for assistive tools", "Signed and encrypted text"));
                    mEdit->setAccessibleDescription(i18nc("@info for assistive tools", "This is the result of the sign and encrypt operation."));
                    break;
                default:;
                }
                break;
            }
            case DecryptVerify: {
                const bool wasDecrypted = decryptVerifyResult && !decryptVerifyResult->decryptionResult().isNull();
                const bool wasVerified = decryptVerifyResult && (decryptVerifyResult->verificationResult().numSignatures() > 0);
                if (wasDecrypted && wasVerified) {
                    mEdit->setAccessibleName(i18nc("@label:textbox for assistive tools", "Decrypted and verified text"));
                    mEdit->setAccessibleDescription(i18nc("@info for assistive tools", "This is the result of decryption and signature verification."));
                } else if (wasDecrypted) {
                    mEdit->setAccessibleName(i18nc("@label:textbox for assistive tools", "Decrypted text"));
                    mEdit->setAccessibleDescription(i18nc("@info for assistive tools", "This is the result of the decryption."));
                } else if (wasVerified) {
                    mEdit->setAccessibleName(i18nc("@label:textbox for assistive tools", "Verified text"));
                    mEdit->setAccessibleDescription(i18nc("@info for assistive tools", "This is the result of the signature verification."));
                }
                break;
            }
            default:
                qCDebug(KLEOPATRA_LOG) << __func__ << "Unexpected last operation:" << mLastOperation;
            };

            setText(QString::fromUtf8(mOutputData));
            mOutputData.clear();
            mRevertBtn->setVisible(true);
        }
    }

    void doDecryptVerify()
    {
        doCryptoCommon();
        mSigEncWidget->clearAddedRecipients();
        startProgress(i18nc("@info:progress", "Decrypting and/or verifying..."));
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
            restoreFocusWidget();
            stopProgress();
            return;
        }
        task->setDataSource(Task::Notepad);

        connect(task, &Task::result, q, [this, task](const std::shared_ptr<const Kleo::Crypto::Task::Result> &result) {
            qCDebug(KLEOPATRA_LOG) << "Decrypt / Verify done. Err:" << result->error().code();
            task->deleteLater();
            cryptDone(result);
        });
        mLastOperation = DecryptVerify;
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
        // remember the current focus widget before we disable any widgets
        saveFocusWidget();
        mCryptBtn->setEnabled(false);
        mDecryptBtn->setEnabled(false);
        mImportBtn->setEnabled(false);
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
            startProgress(i18nc("@info:progress", "Signing notepad..."));
            break;
        case SignEncryptWidget::Encrypt:
            startProgress(i18nc("@info:progress", "Encrypting notepad..."));
            break;
        case SignEncryptWidget::SignAndEncrypt:
            startProgress(i18nc("@info:progress", "Signing and encrypting notepad..."));
            break;
        default:;
        };
        auto input = Input::createFromByteArray(&mInputData, i18n("Notepad"));
        auto output = Output::createFromByteArray(&mOutputData, i18n("Notepad"));

        auto task = new SignEncryptTask();
        task->setInput(input);
        task->setOutput(output);
        task->setDataSource(Task::Notepad);

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
        mLastOperation = SignEncrypt;
        task->start();
    }

    void doImport()
    {
        doCryptoCommon();
        startProgress(i18n("Importing..."));
        auto cmd = new Kleo::ImportCertificateFromDataCommand(mInputData, mImportProto);
        connect(cmd, &Kleo::ImportCertificatesCommand::finished, q, [this]() {
            updateButtons();
            restoreFocusWidget();
            stopProgress();

            mRevertBtn->setVisible(true);
            setText(QString());
        });
        mLastOperation = Import;
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
            if (mMessageWidget->isVisible() && QAccessible::isActive()) {
                mMessageWidget->setFocus();
            }
        }
    }

private:
    PadWidget *const q;

    ApplicationPaletteWatcher appPaletteWatcher;
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
    GpgME::Protocol mImportProto;
    bool mSettingText = false;
    Operation mLastOperation = NoOperation;
    QPointer<QWidget> mFocusWidget;
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
