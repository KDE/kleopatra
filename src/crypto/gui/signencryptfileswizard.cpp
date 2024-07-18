/*  crypto/gui/signencryptfileswizard.cpp

    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2009 Klarälvdalens Datakonsult AB

    SPDX-FileCopyrightText: 2016 Bundesamt für Sicherheit in der Informationstechnik
    SPDX-FileContributor: Intevation GmbH

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include <config-kleopatra.h>

#include "signencryptfileswizard.h"
#include "signencryptwidget.h"

#include "newresultpage.h"

#include <fileoperationspreferences.h>
#include <settings.h>

#include <KColorScheme>
#include <KConfigGroup>
#include <KLocalizedString>
#include <KMessageBox>
#include <KMessageWidget>
#include <KSharedConfig>

#include "kleopatra_debug.h"
#include <Libkleo/Compliance>
#include <Libkleo/Formatting>
#include <Libkleo/GnuPG>
#include <Libkleo/SystemInfo>

#include <Libkleo/FileNameRequester>
#include <QCheckBox>
#include <QGroupBox>
#include <QIcon>
#include <QLabel>
#include <QPushButton>
#include <QStyle>
#include <QVBoxLayout>
#include <QWindow>
#include <QWizardPage>

#include <gpgme++/key.h>

#include <array>

using namespace GpgME;
using namespace Kleo;
using namespace Kleo::Crypto::Gui;

enum Page {
    SigEncPageId,
    ResultPageId,

    NumPages
};

class FileNameRequesterWithIcon : public QWidget
{
    Q_OBJECT

public:
    explicit FileNameRequesterWithIcon(QDir::Filters filter, QWidget *parent = nullptr)
        : QWidget(parent)
    {
        auto layout = new QHBoxLayout{this};
        layout->setContentsMargins(0, 0, 0, 0);
        mIconLabel = new QLabel{this};
        mRequester = new FileNameRequester{filter, this};
        mRequester->setExistingOnly(false);
        layout->addWidget(mIconLabel);
        layout->addWidget(mRequester);

        setFocusPolicy(mRequester->focusPolicy());
        setFocusProxy(mRequester);

        connect(mRequester, &FileNameRequester::fileNameChanged, this, &FileNameRequesterWithIcon::fileNameChanged);
    }

    void setIcon(const QIcon &icon)
    {
        mIconLabel->setPixmap(icon.pixmap(32, 32));
    }

    void setFileName(const QString &name)
    {
        mRequester->setFileName(name);
    }

    QString fileName() const
    {
        return mRequester->fileName();
    }

    void setNameFilter(const QString &nameFilter)
    {
        mRequester->setNameFilter(nameFilter);
    }

    QString nameFilter() const
    {
        return mRequester->nameFilter();
    }

    FileNameRequester *requester()
    {
        return mRequester;
    }

Q_SIGNALS:
    void fileNameChanged(const QString &filename);

protected:
    bool event(QEvent *e) override
    {
        if (e->type() == QEvent::ToolTipChange) {
            mRequester->setToolTip(toolTip());
        }
        return QWidget::event(e);
    }

private:
    QLabel *mIconLabel;
    FileNameRequester *mRequester;
};

class SigEncPage : public QWizardPage
{
    Q_OBJECT

public:
    explicit SigEncPage(QWidget *parent = nullptr)
        : QWizardPage(parent)
        , mParent((SignEncryptFilesWizard *)parent)
        , mWidget(new SignEncryptWidget)
        , mOutLayout(new QVBoxLayout)
        , mOutputLabel{nullptr}
        , mArchive(false)
        , mUseOutputDir(false)
        , mSingleFile{true}
    {
        setTitle(i18nc("@title", "Sign / Encrypt Files"));
        auto vLay = new QVBoxLayout(this);
        vLay->setContentsMargins(0, 0, 0, 0);
        if (!Settings{}.cmsEnabled()) {
            mWidget->setProtocol(GpgME::OpenPGP);
        }
        mWidget->setSignAsText(i18nc("@option:check on SignEncryptPage", "&Sign as:"));
        mWidget->setEncryptForMeText(i18nc("@option:check on SignEncryptPage", "Encrypt for &me:"));
        mWidget->setEncryptForOthersText(i18nc("@option:check on SignEncryptPage", "Encrypt for &others:"));
        mWidget->setEncryptWithPasswordText(
            i18nc("@option:check on SignEncryptPage", "Encrypt with &password. Anyone you share the password with can read the data."));
        vLay->addWidget(mWidget);
        connect(mWidget, &SignEncryptWidget::operationChanged, this, &SigEncPage::updateCommitButton);
        connect(mWidget, &SignEncryptWidget::keysChanged, this, &SigEncPage::updateFileWidgets);

        auto outputGrp = new QGroupBox(i18nc("@title:group", "Output"));
        outputGrp->setLayout(mOutLayout);

        mPlaceholderWidget = new QLabel(i18n("Please select an action."));
        mOutLayout->addWidget(mPlaceholderWidget);

        mOutputLabel = new QLabel(i18nc("@label on SignEncryptPage", "Output &files/folder:"));
        mOutLayout->addWidget(mOutputLabel);

        createRequesters(mOutLayout);

        mUseOutputDirChk = new QCheckBox(i18nc("@option:check on SignEncryptPage", "Encrypt / Sign &each file separately."));
        mUseOutputDirChk->setToolTip(i18nc("@info:tooltip", "Keep each file separate instead of creating an archive for all."));
        mOutLayout->addWidget(mUseOutputDirChk);
        connect(mUseOutputDirChk, &QCheckBox::toggled, this, [this](bool state) {
            mUseOutputDir = state;
            mArchive = !mUseOutputDir && !mSingleFile;
            updateFileWidgets();
        });

        vLay->addWidget(outputGrp);

        auto messageWidget = new KMessageWidget;
        messageWidget->setMessageType(KMessageWidget::Error);
        messageWidget->setIcon(style()->standardIcon(QStyle::SP_MessageBoxCritical, nullptr, this));
        messageWidget->setText(i18n("Invalid compliance settings for signing and encrypting files."));
        messageWidget->setToolTip(xi18nc("@info %1 is a placeholder for the name of a compliance mode. E.g. NATO RESTRICTED compliant or VS-NfD compliant",
                                         "<para>You cannot use <application>Kleopatra</application> for signing or encrypting files "
                                         "because the <application>GnuPG</application> system used by <application>Kleopatra</application> is not %1.</para>",
                                         DeVSCompliance::name(true)));
        messageWidget->setCloseButtonVisible(false);
        messageWidget->setVisible(DeVSCompliance::isActive() && !DeVSCompliance::isCompliant());
        vLay->addWidget(messageWidget);

        setMinimumHeight(300);
    }

    void setEncryptionPreset(bool value)
    {
        mWidget->setEncryptionChecked(value);
    }

    void setSigningPreset(bool value)
    {
        mWidget->setSigningChecked(value);
    }

    bool isComplete() const override
    {
        if (DeVSCompliance::isActive() && !DeVSCompliance::isCompliant()) {
            return false;
        }
        return mWidget->isComplete();
    }

    int nextId() const override
    {
        return ResultPageId;
    }

    void initializePage() override
    {
        setCommitPage(true);
        updateCommitButton(mWidget->currentOp());
    }

    void setArchiveForced(bool archive)
    {
        mArchive = archive;
        setArchiveMutable(!archive);
    }

    void setArchiveMutable(bool archive)
    {
        mUseOutputDirChk->setVisible(archive);
        if (archive) {
            const KConfigGroup archCfg(KSharedConfig::openConfig(), "SignEncryptFilesWizard");
            mUseOutputDirChk->setChecked(archCfg.readEntry("LastUseOutputDir", false));
        } else {
            mUseOutputDirChk->setChecked(false);
        }
    }

    void setSingleFile(bool singleFile)
    {
        mSingleFile = singleFile;
        mArchive = !mUseOutputDir && !mSingleFile;
    }

    bool validatePage() override
    {
        if (DeVSCompliance::isActive() && !DeVSCompliance::isCompliant()) {
            KMessageBox::error(topLevelWidget(),
                               xi18nc("@info %1 is a placeholder for the name of a compliance mode. E.g. NATO RESTRICTED compliant or VS-NfD compliant",
                                      "<para>Sorry! You cannot use <application>Kleopatra</application> for signing or encrypting files "
                                      "because the <application>GnuPG</application> system used by <application>Kleopatra</application> is not %1.</para>",
                                      DeVSCompliance::name(true)));
            return false;
        }
        bool sign = !mWidget->signUserId().isNull();
        bool encrypt = !mWidget->selfUserId().isNull() || !mWidget->recipients().empty();
        if (!mWidget->validate()) {
            return false;
        }
        mWidget->saveOwnKeys();
        if (mUseOutputDirChk->isVisible()) {
            KConfigGroup archCfg(KSharedConfig::openConfig(), "SignEncryptFilesWizard");
            archCfg.writeEntry("LastUseOutputDir", mUseOutputDir);
        }

        if (sign && !encrypt && mArchive) {
            return KMessageBox::warningContinueCancel(
                       this,
                       xi18nc("@info",
                              "<para>Archiving in combination with sign-only currently requires what are known as opaque signatures - "
                              "unlike detached ones, these embed the content in the signature.</para>"
                              "<para>This format is rather unusual. You might want to archive the files separately, "
                              "and then sign the archive as one file with Kleopatra.</para>"
                              "<para>Future versions of Kleopatra are expected to also support detached signatures in this case.</para>"),
                       i18nc("@title:window", "Unusual Signature Warning"),
                       KStandardGuiItem::cont(),
                       KStandardGuiItem::cancel(),
                       QStringLiteral("signencryptfileswizard-archive+sign-only-warning"))
                == KMessageBox::Continue;
        } else if (sign && !encrypt) {
            return true;
        }

        if (!mWidget->selfUserId().isNull() || mWidget->encryptSymmetric()) {
            return true;
        }
        const auto recipientKeys = recipients();
        const bool hasSecret = std::any_of(std::begin(recipientKeys), std::end(recipientKeys), [](const auto &k) {
            return k.hasSecret();
        });
        if (!hasSecret) {
            if (KMessageBox::warningContinueCancel(this,
                                                   xi18nc("@info",
                                                          "<para>None of the recipients you are encrypting to seems to be your own.</para>"
                                                          "<para>This means that you will not be able to decrypt the data anymore, once encrypted.</para>"
                                                          "<para>Do you want to continue, or cancel to change the recipient selection?</para>"),
                                                   i18nc("@title:window", "Encrypt-To-Self Warning"),
                                                   KStandardGuiItem::cont(),
                                                   KStandardGuiItem::cancel(),
                                                   QStringLiteral("warn-encrypt-to-non-self"),
                                                   KMessageBox::Notify | KMessageBox::Dangerous)
                == KMessageBox::Cancel) {
                return false;
            }
        }
        return true;
    }

    std::vector<Key> recipients() const
    {
        return mWidget->recipients();
    }

    /* In the future we might find a usecase for multiple
     * signers */
    std::vector<Key> signers() const
    {
        const Key k = mWidget->signUserId().parent();
        if (!k.isNull()) {
            return {k};
        }
        return {};
    }

private:
    struct RequesterInfo {
        SignEncryptFilesWizard::KindNames id;
        QString icon;
        QString toolTip;
        QString accessibleName;
        QString nameFilterBinary;
        QString nameFilterAscii;
    };
    void createRequesters(QBoxLayout *lay)
    {
        static const std::array<RequesterInfo, 6> requestersInfo = {{
            {
                SignEncryptFilesWizard::SignatureCMS,
                QStringLiteral("document-sign"),
                i18nc("@info:tooltip", "This is the filename of the S/MIME signature."),
                i18nc("Lineedit accessible name", "S/MIME signature file"),
                i18nc("Name filter binary", "S/MIME Signatures (*.p7s)"),
                i18nc("Name filter ASCII", "S/MIME Signatures (*.p7s *.pem)"),
            },
            {
                SignEncryptFilesWizard::SignaturePGP,
                QStringLiteral("document-sign"),
                i18nc("@info:tooltip", "This is the filename of the detached OpenPGP signature."),
                i18nc("Lineedit accessible name", "OpenPGP signature file"),
                i18nc("Name filter binary", "OpenPGP Signatures (*.sig *.pgp)"),
                i18nc("Name filter ASCII", "OpenPGP Signatures (*.asc *.sig)"),
            },
            {
                SignEncryptFilesWizard::CombinedPGP,
                QStringLiteral("document-edit-sign-encrypt"),
                i18nc("@info:tooltip", "This is the filename of the OpenPGP-signed and encrypted file."),
                i18nc("Lineedit accessible name", "OpenPGP signed and encrypted file"),
                i18nc("Name filter binary", "OpenPGP Files (*.gpg *.pgp)"),
                i18nc("Name filter ASCII", "OpenPGP Files (*.asc)"),
            },
            {
                SignEncryptFilesWizard::EncryptedPGP,
                QStringLiteral("document-encrypt"),
                i18nc("@info:tooltip", "This is the filename of the OpenPGP encrypted file."),
                i18nc("Lineedit accessible name", "OpenPGP encrypted file"),
                i18nc("Name filter binary", "OpenPGP Files (*.gpg *.pgp)"),
                i18nc("Name filter ASCII", "OpenPGP Files (*.asc)"),
            },
            {
                SignEncryptFilesWizard::EncryptedCMS,
                QStringLiteral("document-encrypt"),
                i18nc("@info:tooltip", "This is the filename of the S/MIME encrypted file."),
                i18nc("Lineedit accessible name", "S/MIME encrypted file"),
                i18nc("Name filter binary", "S/MIME Files (*.p7m)"),
                i18nc("Name filter ASCII", "S/MIME Files (*.p7m *.pem)"),
            },
            {
                SignEncryptFilesWizard::Directory,
                QStringLiteral("folder"),
                i18nc("@info:tooltip", "The resulting files are written to this directory."),
                i18nc("Lineedit accessible name", "Output directory"),
                {},
                {},
            },
        }};

        if (!mRequesters.empty()) {
            return;
        }
        const bool isAscii = FileOperationsPreferences().addASCIIArmor();
        for (const auto &requester : requestersInfo) {
            const auto id = requester.id;
            auto requesterWithIcon = new FileNameRequesterWithIcon{id == SignEncryptFilesWizard::Directory ? QDir::Dirs : QDir::Files, this};
            requesterWithIcon->setIcon(QIcon::fromTheme(requester.icon));
            requesterWithIcon->setToolTip(requester.toolTip);
            requesterWithIcon->requester()->setAccessibleNameOfLineEdit(requester.accessibleName);
            requesterWithIcon->setNameFilter(isAscii ? requester.nameFilterAscii : requester.nameFilterBinary);
            lay->addWidget(requesterWithIcon);

            connect(requesterWithIcon, &FileNameRequesterWithIcon::fileNameChanged, this, [this, id](const QString &newName) {
                mOutNames[id] = newName;
            });

            mRequesters.insert(id, requesterWithIcon);
        }
    }

public:
    void setOutputNames(const QMap<int, QString> &names)
    {
        Q_ASSERT(mOutNames.isEmpty());
        for (auto it = std::begin(names); it != std::end(names); ++it) {
            mRequesters.value(it.key())->setFileName(it.value());
        }
        mOutNames = names;
        updateFileWidgets();
    }

    QMap<int, QString> outputNames() const
    {
        if (!mUseOutputDir) {
            auto ret = mOutNames;
            ret.remove(SignEncryptFilesWizard::Directory);
            return ret;
        }
        return mOutNames;
    }

    bool encryptSymmetric() const
    {
        return mWidget->encryptSymmetric();
    }

private Q_SLOTS:
    void updateCommitButton(const SignEncryptWidget::Operations op)
    {
        if (mParent->currentPage() != this) {
            return;
        }
        QString label;
        switch (op) {
        case SignEncryptWidget::Sign:
            label = i18nc("@action:button", "Sign");
            break;
        case SignEncryptWidget::Encrypt:
            label = i18nc("@action:button", "Encrypt");
            break;
        case SignEncryptWidget::SignAndEncrypt:
            label = i18nc("@action:button", "Sign / Encrypt");
            break;
        default:;
        };
        auto btn = qobject_cast<QPushButton *>(mParent->button(QWizard::CommitButton));
        if (!label.isEmpty()) {
            mParent->setButtonText(QWizard::CommitButton, label);
            if (DeVSCompliance::isActive()) {
                const bool de_vs = DeVSCompliance::isCompliant() && mWidget->isDeVsAndValid();
                DeVSCompliance::decorate(btn, de_vs);
                mParent->setLabelText(DeVSCompliance::name(de_vs));
            }
        } else {
            mParent->setButtonText(QWizard::CommitButton, i18n("Next"));
            btn->setIcon(QIcon());
            btn->setStyleSheet(QString());
        }
        Q_EMIT completeChanged();
    }

    void updateFileWidgets()
    {
        if (mRequesters.isEmpty()) {
            return;
        }
        const std::vector<Key> recipients = mWidget->recipients();
        const Key sigKey = mWidget->signUserId().parent();
        const bool pgp = mWidget->encryptSymmetric() || std::any_of(std::cbegin(recipients), std::cend(recipients), [](const auto &k) {
                             return k.protocol() == Protocol::OpenPGP;
                         });
        const bool cms = std::any_of(std::cbegin(recipients), std::cend(recipients), [](const auto &k) {
            return k.protocol() == Protocol::CMS;
        });

        mOutLayout->setEnabled(false);
        if (cms || pgp || !sigKey.isNull()) {
            mPlaceholderWidget->setVisible(false);
            mOutputLabel->setVisible(true);
            mRequesters[SignEncryptFilesWizard::SignatureCMS]->setVisible(!mUseOutputDir && sigKey.protocol() == Protocol::CMS);
            mRequesters[SignEncryptFilesWizard::EncryptedCMS]->setVisible(!mUseOutputDir && cms);
            mRequesters[SignEncryptFilesWizard::CombinedPGP]->setVisible(!mUseOutputDir && sigKey.protocol() == Protocol::OpenPGP && pgp);
            mRequesters[SignEncryptFilesWizard::EncryptedPGP]->setVisible(!mUseOutputDir && sigKey.protocol() != Protocol::OpenPGP && pgp);
            mRequesters[SignEncryptFilesWizard::SignaturePGP]->setVisible(!mUseOutputDir && sigKey.protocol() == Protocol::OpenPGP && !pgp);
            mRequesters[SignEncryptFilesWizard::Directory]->setVisible(mUseOutputDir);
            auto firstNotHidden = std::find_if(std::cbegin(mRequesters), std::cend(mRequesters), [](auto w) {
                return !w->isHidden();
            });
            mOutputLabel->setBuddy(*firstNotHidden);
        } else {
            mPlaceholderWidget->setVisible(true);
            mOutputLabel->setVisible(false);
            std::for_each(std::cbegin(mRequesters), std::cend(mRequesters), [](auto w) {
                w->setVisible(false);
            });
            mOutputLabel->setBuddy(nullptr);
        }
        mOutLayout->setEnabled(true);
    }

private:
    SignEncryptFilesWizard *mParent;
    SignEncryptWidget *mWidget;
    QMap<int, QString> mOutNames;
    QMap<int, FileNameRequesterWithIcon *> mRequesters;
    QVBoxLayout *mOutLayout;
    QWidget *mPlaceholderWidget;
    QCheckBox *mUseOutputDirChk;
    QLabel *mOutputLabel;
    bool mArchive;
    bool mUseOutputDir;
    bool mSingleFile;
};

class ResultPage : public NewResultPage
{
    Q_OBJECT

public:
    explicit ResultPage(QWidget *parent = nullptr)
        : NewResultPage(parent)
        , mParent((SignEncryptFilesWizard *)parent)
    {
        setTitle(i18nc("@title", "Results"));
        setSubTitle(i18nc("@title", "Status and progress of the crypto operations is shown here."));
    }

    void initializePage() override
    {
        mParent->setLabelText(QString());
    }

private:
    SignEncryptFilesWizard *mParent;
};

SignEncryptFilesWizard::SignEncryptFilesWizard(QWidget *parent, Qt::WindowFlags f)
    : QWizard(parent, f)
{
    readConfig();

    const bool de_vs = DeVSCompliance::isActive();
#ifdef Q_OS_WIN
    // Enforce modern style to avoid vista style ugliness.
    setWizardStyle(QWizard::ModernStyle);
#endif
    mSigEncPage = new SigEncPage(this);
    mResultPage = new ResultPage(this);

    connect(this, &QWizard::currentIdChanged, this, &SignEncryptFilesWizard::slotCurrentIdChanged);
    setPage(SigEncPageId, mSigEncPage);
    setPage(ResultPageId, mResultPage);
    setOptions(QWizard::IndependentPages | //
               (de_vs ? QWizard::HaveCustomButton1 : QWizard::WizardOption(0)) | //
               QWizard::NoBackButtonOnLastPage | //
               QWizard::NoBackButtonOnStartPage);

    if (de_vs) {
        /* We use a custom button to display a label next to the
           buttons.  */
        auto btn = button(QWizard::CustomButton1);
        /* We style the button so that it looks and acts like a
           label.  */
        btn->setStyleSheet(QStringLiteral("border: none"));
        btn->setFocusPolicy(Qt::NoFocus);
    }
}

void SignEncryptFilesWizard::setLabelText(const QString &label)
{
    button(QWizard::CommitButton)->setToolTip(label);
    setButtonText(QWizard::CustomButton1, label);
}

void SignEncryptFilesWizard::slotCurrentIdChanged(int id)
{
    if (id == ResultPageId) {
        Q_EMIT operationPrepared();
    }
}

SignEncryptFilesWizard::~SignEncryptFilesWizard()
{
    qCDebug(KLEOPATRA_LOG) << this << __func__;
    writeConfig();
}

void SignEncryptFilesWizard::setSigningPreset(bool preset)
{
    mSigEncPage->setSigningPreset(preset);
}

void SignEncryptFilesWizard::setSigningUserMutable(bool mut)
{
    if (mut == mSigningUserMutable) {
        return;
    }
    mSigningUserMutable = mut;
}

void SignEncryptFilesWizard::setEncryptionPreset(bool preset)
{
    mSigEncPage->setEncryptionPreset(preset);
}

void SignEncryptFilesWizard::setEncryptionUserMutable(bool mut)
{
    if (mut == mEncryptionUserMutable) {
        return;
    }
    mEncryptionUserMutable = mut;
}

void SignEncryptFilesWizard::setArchiveForced(bool archive)
{
    mSigEncPage->setArchiveForced(archive);
}

void SignEncryptFilesWizard::setArchiveMutable(bool archive)
{
    mSigEncPage->setArchiveMutable(archive);
}

void SignEncryptFilesWizard::setSingleFile(bool singleFile)
{
    mSigEncPage->setSingleFile(singleFile);
}

std::vector<Key> SignEncryptFilesWizard::resolvedRecipients() const
{
    return mSigEncPage->recipients();
}

std::vector<Key> SignEncryptFilesWizard::resolvedSigners() const
{
    return mSigEncPage->signers();
}

void SignEncryptFilesWizard::setTaskCollection(const std::shared_ptr<Kleo::Crypto::TaskCollection> &coll)
{
    mResultPage->setTaskCollection(coll);
}

void SignEncryptFilesWizard::setOutputNames(const QMap<int, QString> &map) const
{
    mSigEncPage->setOutputNames(map);
}

QMap<int, QString> SignEncryptFilesWizard::outputNames() const
{
    return mSigEncPage->outputNames();
}

bool SignEncryptFilesWizard::encryptSymmetric() const
{
    return mSigEncPage->encryptSymmetric();
}

void SignEncryptFilesWizard::readConfig()
{
    KConfigGroup dialog(KSharedConfig::openStateConfig(), QStringLiteral("SignEncryptFilesWizard"));
    const QSize size = dialog.readEntry("Size", QSize(640, 480));
    if (size.isValid()) {
        resize(size);
    }
}

void SignEncryptFilesWizard::writeConfig()
{
    KConfigGroup dialog(KSharedConfig::openStateConfig(), QStringLiteral("SignEncryptFilesWizard"));
    dialog.writeEntry("Size", size());
    dialog.sync();
}

#include "signencryptfileswizard.moc"
