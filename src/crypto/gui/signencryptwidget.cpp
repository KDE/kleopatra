/*  crypto/gui/signencryptwidget.cpp

    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2016 Bundesamt für Sicherheit in der Informationstechnik
    SPDX-FileContributor: Intevation GmbH

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include "signencryptwidget.h"

#include "kleopatra_debug.h"

#include "certificatelineedit.h"
#include "fileoperationspreferences.h"
#include "kleopatraapplication.h"
#include "settings.h"
#include "unknownrecipientwidget.h"

#include "dialogs/certificateselectiondialog.h"
#include "utils/gui-helper.h"

#include <QCheckBox>
#include <QGroupBox>
#include <QHBoxLayout>
#include <QLabel>
#include <QScrollArea>
#include <QScrollBar>
#include <QVBoxLayout>

#include <Libkleo/Algorithm>
#include <Libkleo/Compliance>
#include <Libkleo/DefaultKeyFilter>
#include <Libkleo/ExpiryChecker>
#include <Libkleo/ExpiryCheckerConfig>
#include <Libkleo/ExpiryCheckerSettings>
#include <Libkleo/KeyCache>
#include <Libkleo/KeyHelpers>
#include <Libkleo/KeyListModel>
#include <Libkleo/KeyListSortFilterProxyModel>
#include <Libkleo/UserIDSelectionCombo>

#include <Libkleo/GnuPG>

#include <KConfigGroup>
#include <KLocalizedString>
#include <KMessageBox>
#include <KMessageWidget>
#include <KSharedConfig>

using namespace Kleo;
using namespace Kleo::Dialogs;
using namespace GpgME;

namespace
{
class SignCertificateFilter : public DefaultKeyFilter
{
public:
    SignCertificateFilter(GpgME::Protocol proto)
        : DefaultKeyFilter()
    {
        setRevoked(DefaultKeyFilter::NotSet);
        setExpired(DefaultKeyFilter::NotSet);
        setHasSecret(DefaultKeyFilter::Set);
        setCanSign(DefaultKeyFilter::Set);
        setValidIfSMIME(DefaultKeyFilter::Set);

        if (proto == GpgME::OpenPGP) {
            setIsOpenPGP(DefaultKeyFilter::Set);
        } else if (proto == GpgME::CMS) {
            setIsOpenPGP(DefaultKeyFilter::NotSet);
        }
    }
};
class EncryptCertificateFilter : public DefaultKeyFilter
{
public:
    EncryptCertificateFilter(GpgME::Protocol proto)
        : DefaultKeyFilter()
    {
        setRevoked(DefaultKeyFilter::NotSet);
        setExpired(DefaultKeyFilter::NotSet);
        setCanEncrypt(DefaultKeyFilter::Set);
        setValidIfSMIME(DefaultKeyFilter::Set);

        if (proto == GpgME::OpenPGP) {
            setIsOpenPGP(DefaultKeyFilter::Set);
        } else if (proto == GpgME::CMS) {
            setIsOpenPGP(DefaultKeyFilter::NotSet);
        }
    }
};
class EncryptSelfCertificateFilter : public EncryptCertificateFilter
{
public:
    EncryptSelfCertificateFilter(GpgME::Protocol proto)
        : EncryptCertificateFilter(proto)
    {
        setRevoked(DefaultKeyFilter::NotSet);
        setExpired(DefaultKeyFilter::NotSet);
        setCanEncrypt(DefaultKeyFilter::Set);
        setHasSecret(DefaultKeyFilter::Set);
        setValidIfSMIME(DefaultKeyFilter::Set);
    }
};
}

class SignEncryptWidget::Private
{
    SignEncryptWidget *const q;

public:
    struct RecipientWidgets {
        CertificateLineEdit *edit;
        KMessageWidget *expiryMessage;
    };

    explicit Private(SignEncryptWidget *qq, bool sigEncExclusive)
        : q{qq}
        , mModel{AbstractKeyListModel::createFlatKeyListModel(qq)}
        , mIsExclusive{sigEncExclusive}
    {
    }

    CertificateLineEdit *addRecipientWidget();
    /* Inserts a new recipient widget after widget @p after or at the end
     * if @p after is null. */
    CertificateLineEdit *insertRecipientWidget(CertificateLineEdit *after);
    void recpRemovalRequested(const RecipientWidgets &recipient);
    void onProtocolChanged();
    void updateCheckBoxes();
    ExpiryChecker *expiryChecker();
    void updateExpiryMessages(KMessageWidget *w, const GpgME::Key &key, ExpiryChecker::CheckFlags flags);
    void updateAllExpiryMessages();

public:
    UserIDSelectionCombo *mSigSelect = nullptr;
    KMessageWidget *mSignKeyExpiryMessage = nullptr;
    UserIDSelectionCombo *mSelfSelect = nullptr;
    KMessageWidget *mEncryptToSelfKeyExpiryMessage = nullptr;
    std::vector<RecipientWidgets> mRecpWidgets;
    QList<UnknownRecipientWidget *> mUnknownWidgets;
    QList<GpgME::Key> mAddedKeys;
    QList<KeyGroup> mAddedGroups;
    QVBoxLayout *mRecpLayout = nullptr;
    Operations mOp;
    AbstractKeyListModel *mModel = nullptr;
    QCheckBox *mSymmetric = nullptr;
    QLabel *mSigChk = nullptr;
    QLabel *mEncOtherLabel = nullptr;
    QLabel *mEncSelfChk = nullptr;
    GpgME::Protocol mCurrentProto = GpgME::UnknownProtocol;
    const bool mIsExclusive;
    std::unique_ptr<ExpiryChecker> mExpiryChecker;
};

SignEncryptWidget::SignEncryptWidget(QWidget *parent, bool sigEncExclusive)
    : QWidget{parent}
    , d{new Private{this, sigEncExclusive}}
{
    auto lay = new QVBoxLayout(this);
    lay->setContentsMargins(0, 0, 0, 0);

    d->mModel->useKeyCache(true, KeyList::IncludeGroups);

    const bool haveSecretKeys = !KeyCache::instance()->secretKeys().empty();
    const bool havePublicKeys = !KeyCache::instance()->keys().empty();
    const bool symmetricOnly = FileOperationsPreferences().symmetricEncryptionOnly();

    /* The signature selection */
    {
        auto sigGrp = new QGroupBox{i18nc("@title:group", "Prove authenticity (sign)"), this};
        d->mSigChk = new QLabel{i18n("Sign as:"), this};
        d->mSigChk->setEnabled(haveSecretKeys);
        // d->mSigChk->setChecked(haveSecretKeys);

        d->mSigSelect = new UserIDSelectionCombo{KeyUsage::Sign, this};
        d->mSigSelect->prependCustomItem(QIcon::fromTheme(QStringLiteral("edit-none")), i18n("Do not sign"), {});
        // d->mSigSelect->setEnabled(d->mSigChk->isChecked());

        d->mSignKeyExpiryMessage = new KMessageWidget{this};
        d->mSignKeyExpiryMessage->setVisible(false);

        auto groupLayout = new QGridLayout{sigGrp};
        groupLayout->setColumnStretch(1, 1);
        groupLayout->addWidget(d->mSigChk, 0, 0);
        groupLayout->addWidget(d->mSigSelect, 0, 1);
        groupLayout->addWidget(d->mSignKeyExpiryMessage, 1, 1);
        lay->addWidget(sigGrp);

        // connect(d->mSigChk, &QCheckBox::toggled, this, [this](bool checked) {
        //     d->mSigSelect->setEnabled(checked);
        //     updateOp();
        //     d->updateExpiryMessages(d->mSignKeyExpiryMessage, signKey(), ExpiryChecker::OwnSigningKey);
        // });
        connect(d->mSigSelect, &UserIDSelectionCombo::currentKeyChanged, this, [this]() {
            updateOp();
            d->updateExpiryMessages(d->mSignKeyExpiryMessage, signKey(), ExpiryChecker::OwnSigningKey);
        });
    }

    // Recipient selection
    {
        auto encBox = new QGroupBox{i18nc("@title:group", "Encrypt"), this};
        auto encBoxLay = new QVBoxLayout{encBox};
        auto recipientGrid = new QGridLayout;
        int row = 0;

        // Own key
        d->mEncSelfChk = new QLabel{i18n("Encrypt for me:"), this};
        d->mEncSelfChk->setEnabled(haveSecretKeys && !symmetricOnly);
        // d->mEncSelfChk->setChecked(haveSecretKeys && !symmetricOnly);
        d->mSelfSelect = new UserIDSelectionCombo{KeyUsage::Encrypt, this};
        d->mSelfSelect->prependCustomItem(QIcon::fromTheme(QStringLiteral("edit-none")), i18n("Do not encrypt for me"), {});
        // d->mSelfSelect->setEnabled(d->mEncSelfChk->isChecked());
        d->mEncryptToSelfKeyExpiryMessage = new KMessageWidget{this};
        d->mEncryptToSelfKeyExpiryMessage->setVisible(false);
        recipientGrid->addWidget(d->mEncSelfChk, row, 0);
        recipientGrid->addWidget(d->mSelfSelect, row, 1);
        row++;
        recipientGrid->addWidget(d->mEncryptToSelfKeyExpiryMessage, row, 1);

        // Checkbox for other keys
        row++;
        d->mEncOtherLabel = new QLabel{i18n("Encrypt for others:"), this};
        recipientGrid->addWidget(d->mEncOtherLabel, row, 0, Qt::AlignTop | Qt::AlignRight);
        d->mRecpLayout = new QVBoxLayout;
        recipientGrid->addLayout(d->mRecpLayout, row, 1);
        recipientGrid->setRowStretch(row + 1, 1);

        // Scroll area for other keys
        auto recipientWidget = new QWidget;
        auto recipientScroll = new QScrollArea;
        recipientWidget->setLayout(recipientGrid);
        recipientScroll->setWidget(recipientWidget);
        recipientScroll->setWidgetResizable(true);
        recipientScroll->setSizeAdjustPolicy(QAbstractScrollArea::AdjustToContentsOnFirstShow);
        recipientScroll->setFrameStyle(QFrame::NoFrame);
        recipientScroll->setFocusPolicy(Qt::NoFocus);
        recipientGrid->setContentsMargins(0, 0, 0, 0);
        encBoxLay->addWidget(recipientScroll, 1);

        auto bar = recipientScroll->verticalScrollBar();
        connect(bar, &QScrollBar::rangeChanged, this, [bar](int, int max) {
            bar->setValue(max);
        });

        auto certLineEdit = d->addRecipientWidget();
        if (d->mIsExclusive) {
            connect(certLineEdit, &CertificateLineEdit::keyChanged, this, [this]() {
                if (d->mCurrentProto != GpgME::CMS) {
                    return;
                }
                // d->mSigChk->setChecked(false);
            });
        }

        // Checkbox for password
        d->mSymmetric = new QCheckBox(i18n("Encrypt with password. Anyone you share the password with can read the data."));
        d->mSymmetric->setToolTip(i18nc("Tooltip information for symmetric encryption",
                                        "Additionally to the keys of the recipients you can encrypt your data with a password. "
                                        "Anyone who has the password can read the data without any secret key. "
                                        "Using a password is <b>less secure</b> then public key cryptography. Even if you pick a very strong password."));
        d->mSymmetric->setChecked(symmetricOnly || !havePublicKeys);
        encBoxLay->addWidget(d->mSymmetric);

        // Connect it
        connect(d->mSelfSelect, &UserIDSelectionCombo::currentIndexChanged, this, [this]() {
            updateOp();
            d->updateExpiryMessages(d->mEncryptToSelfKeyExpiryMessage, selfKey(), ExpiryChecker::OwnEncryptionKey);
        });
        connect(d->mSymmetric, &QCheckBox::toggled, this, &SignEncryptWidget::updateOp);

        if (d->mIsExclusive) {
            connect(d->mSelfSelect, &UserIDSelectionCombo::currentIndexChanged, this, [this](const auto index) {
                if (d->mCurrentProto != GpgME::CMS) {
                    return;
                }
                if (index != 0) {
                    d->mSigSelect->setCurrentIndex(0);
                }
            });
            connect(d->mSigSelect, &UserIDSelectionCombo::currentIndexChanged, this, [this](const auto index) {
                if (d->mCurrentProto != GpgME::CMS) {
                    return;
                }
                if (index != 0) {
                    d->mSelfSelect->setCurrentIndex(0);
                    // Copying the vector makes sure that all items are actually deleted.
                    for (const auto &widget : std::vector(d->mRecpWidgets)) {
                        d->recpRemovalRequested(widget);
                    }
                    d->addRecipientWidget();
                }
            });
        }

        // Ensure that the d->mSigChk is aligned together with the encryption check boxes.
        d->mSigChk->setMinimumWidth(qMax(d->mEncOtherLabel->width(), d->mEncSelfChk->width()));

        lay->addWidget(encBox);
    }

    connect(KeyCache::instance().get(), &Kleo::KeyCache::keysMayHaveChanged, this, [this]() {
        d->updateCheckBoxes();
        d->updateAllExpiryMessages();
    });
    connect(KleopatraApplication::instance(), &KleopatraApplication::configurationChanged, this, [this]() {
        d->updateCheckBoxes();
        d->mExpiryChecker.reset();
        d->updateAllExpiryMessages();
    });

    loadKeys();
    d->onProtocolChanged();
    updateOp();
}

SignEncryptWidget::~SignEncryptWidget() = default;

void SignEncryptWidget::setEncryptWithPasswordText(const QString &text)
{
    d->mSymmetric->setText(text);
}

CertificateLineEdit *SignEncryptWidget::Private::addRecipientWidget()
{
    return insertRecipientWidget(nullptr);
}

CertificateLineEdit *SignEncryptWidget::Private::insertRecipientWidget(CertificateLineEdit *after)
{
    Q_ASSERT(!after || mRecpLayout->indexOf(after) != -1);

    const auto index = after ? mRecpLayout->indexOf(after) + 2 : mRecpLayout->count();

    const RecipientWidgets recipient{new CertificateLineEdit{mModel, KeyUsage::Encrypt, new EncryptCertificateFilter{mCurrentProto}, q}, new KMessageWidget{q}};
    recipient.edit->setAccessibleNameOfLineEdit(i18nc("text for screen readers", "recipient key"));
    recipient.expiryMessage->setVisible(false);
    if (static_cast<unsigned>(index / 2) < mRecpWidgets.size()) {
        mRecpWidgets.insert(mRecpWidgets.begin() + index / 2, recipient);
    } else {
        mRecpWidgets.push_back(recipient);
    }

    if (mRecpLayout->count() > 0) {
        auto prevWidget = after ? after : mRecpLayout->itemAt(mRecpLayout->count() - 1)->widget();
        Kleo::forceSetTabOrder(prevWidget, recipient.edit);
        Kleo::forceSetTabOrder(recipient.edit, recipient.expiryMessage);
    }
    mRecpLayout->insertWidget(index, recipient.edit);
    mRecpLayout->insertWidget(index + 1, recipient.expiryMessage);

    connect(recipient.edit, &CertificateLineEdit::keyChanged, q, &SignEncryptWidget::recipientsChanged);
    connect(recipient.edit, &CertificateLineEdit::editingStarted, q, &SignEncryptWidget::recipientsChanged);
    connect(recipient.edit, &CertificateLineEdit::cleared, q, &SignEncryptWidget::recipientsChanged);
    connect(recipient.edit, &CertificateLineEdit::certificateSelectionRequested, q, [this, recipient]() {
        q->certificateSelectionRequested(recipient.edit);
    });

    if (mIsExclusive) {
        connect(recipient.edit, &CertificateLineEdit::keyChanged, q, [this]() {
            mSigSelect->setCurrentIndex(0);
        });
    }

    return recipient.edit;
}

void SignEncryptWidget::addRecipient(const Key &key)
{
    CertificateLineEdit *certSel = d->addRecipientWidget();
    if (!key.isNull()) {
        certSel->setKey(key);
        d->mAddedKeys << key;
    }
}

void SignEncryptWidget::addRecipient(const KeyGroup &group)
{
    CertificateLineEdit *certSel = d->addRecipientWidget();
    if (!group.isNull()) {
        certSel->setGroup(group);
        d->mAddedGroups << group;
    }
}

void SignEncryptWidget::certificateSelectionRequested(CertificateLineEdit *certificateLineEdit)
{
    CertificateSelectionDialog dlg{this};

    dlg.setOptions(CertificateSelectionDialog::Options( //
        CertificateSelectionDialog::MultiSelection | //
        CertificateSelectionDialog::EncryptOnly | //
        CertificateSelectionDialog::optionsFromProtocol(d->mCurrentProto) | //
        CertificateSelectionDialog::IncludeGroups));

    if (!certificateLineEdit->key().isNull()) {
        const auto key = certificateLineEdit->key();
        const auto name = QString::fromUtf8(key.userID(0).name());
        const auto email = QString::fromUtf8(key.userID(0).email());
        dlg.setStringFilter(!name.isEmpty() ? name : email);
    } else if (!certificateLineEdit->group().isNull()) {
        dlg.setStringFilter(certificateLineEdit->group().name());
    } else if (!certificateLineEdit->userID().isNull()) {
        const auto userID = certificateLineEdit->userID();
        const auto name = QString::fromUtf8(userID.name());
        const auto email = QString::fromUtf8(userID.email());
        dlg.setStringFilter(!name.isEmpty() ? name : email);
    } else {
        dlg.setStringFilter(certificateLineEdit->text());
    }

    if (dlg.exec()) {
        const std::vector<UserID> userIds = dlg.selectedUserIDs();
        const std::vector<KeyGroup> groups = dlg.selectedGroups();
        if (userIds.size() == 0 && groups.size() == 0) {
            return;
        }
        CertificateLineEdit *certWidget = nullptr;
        for (const auto &userId : userIds) {
            if (!certWidget) {
                certWidget = certificateLineEdit;
            } else {
                certWidget = d->insertRecipientWidget(certWidget);
            }
            certWidget->setUserID(userId);
        }
        for (const KeyGroup &group : groups) {
            if (!certWidget) {
                certWidget = certificateLineEdit;
            } else {
                certWidget = d->insertRecipientWidget(certWidget);
            }
            certWidget->setGroup(group);
        }
    }

    recipientsChanged();
}

void SignEncryptWidget::clearAddedRecipients()
{
    for (auto w : std::as_const(d->mUnknownWidgets)) {
        d->mRecpLayout->removeWidget(w);
        delete w;
    }

    for (auto &key : std::as_const(d->mAddedKeys)) {
        removeRecipient(key);
    }

    for (auto &group : std::as_const(d->mAddedGroups)) {
        removeRecipient(group);
    }
}

void SignEncryptWidget::addUnknownRecipient(const char *keyID)
{
    auto unknownWidget = new UnknownRecipientWidget(keyID);
    d->mUnknownWidgets << unknownWidget;

    if (d->mRecpLayout->count() > 0) {
        auto lastWidget = d->mRecpLayout->itemAt(d->mRecpLayout->count() - 1)->widget();
        setTabOrder(lastWidget, unknownWidget);
    }
    d->mRecpLayout->addWidget(unknownWidget);

    connect(KeyCache::instance().get(), &Kleo::KeyCache::keysMayHaveChanged, this, [this]() {
        // Check if any unknown recipient can now be found.
        for (auto w : d->mUnknownWidgets) {
            auto key = KeyCache::instance()->findByKeyIDOrFingerprint(w->keyID().toLatin1().constData());
            if (key.isNull()) {
                std::vector<std::string> subids;
                subids.push_back(std::string(w->keyID().toLatin1().constData()));
                for (const auto &subkey : KeyCache::instance()->findSubkeysByKeyID(subids)) {
                    key = subkey.parent();
                }
            }
            if (key.isNull()) {
                continue;
            }
            // Key is now available replace by line edit.
            qCDebug(KLEOPATRA_LOG) << "Removing widget for keyid: " << w->keyID();
            d->mRecpLayout->removeWidget(w);
            d->mUnknownWidgets.removeAll(w);
            delete w;
            addRecipient(key);
        }
    });
}

void SignEncryptWidget::recipientsChanged()
{
    const bool hasEmptyRecpWidget = std::any_of(std::cbegin(d->mRecpWidgets), std::cend(d->mRecpWidgets), [](auto w) {
        return w.edit->isEmpty();
    });
    if (!hasEmptyRecpWidget) {
        d->addRecipientWidget();
    }
    updateOp();
    for (const auto &recipient : std::as_const(d->mRecpWidgets)) {
        if (!recipient.edit->isEditingInProgress() || recipient.edit->isEmpty()) {
            d->updateExpiryMessages(recipient.expiryMessage, recipient.edit->userID().parent(), ExpiryChecker::EncryptionKey);
        }
    }
}

Key SignEncryptWidget::signKey() const
{
    if (d->mSigSelect->isEnabled()) {
        return d->mSigSelect->currentKey();
    }
    return Key();
}

Key SignEncryptWidget::selfKey() const
{
    if (d->mSelfSelect->isEnabled()) {
        return d->mSelfSelect->currentKey();
    }
    return Key();
}

std::vector<Key> SignEncryptWidget::recipients() const
{
    std::vector<Key> ret;
    for (const auto &recipient : std::as_const(d->mRecpWidgets)) {
        const auto *const w = recipient.edit;
        if (!w->isEnabled()) {
            // If one is disabled, all are disabled.
            break;
        }
        const Key k = w->key();
        const KeyGroup g = w->group();
        const UserID u = w->userID();
        if (!k.isNull()) {
            ret.push_back(k);
        } else if (!g.isNull()) {
            const auto keys = g.keys();
            std::copy(keys.begin(), keys.end(), std::back_inserter(ret));
        } else if (!u.isNull()) {
            ret.push_back(u.parent());
        }
    }
    const Key k = selfKey();
    if (!k.isNull()) {
        ret.push_back(k);
    }
    return ret;
}

bool SignEncryptWidget::isDeVsAndValid() const
{
    if (!signKey().isNull() && !DeVSCompliance::keyIsCompliant(signKey())) {
        return false;
    }

    if (!selfKey().isNull() && !DeVSCompliance::keyIsCompliant(selfKey())) {
        return false;
    }

    for (const auto &key : recipients()) {
        if (!DeVSCompliance::keyIsCompliant(key)) {
            return false;
        }
    }

    return true;
}

static QString expiryMessage(const ExpiryChecker::Result &result)
{
    if (result.expiration.certificate.isNull()) {
        return {};
    }
    switch (result.expiration.status) {
    case ExpiryChecker::Expired:
        return i18nc("@info", "This certificate is expired.");
    case ExpiryChecker::ExpiresSoon: {
        if (result.expiration.duration.count() == 0) {
            return i18nc("@info", "This certificate expires today.");
        } else {
            return i18ncp("@info", "This certificate expires tomorrow.", "This certificate expires in %1 days.", result.expiration.duration.count());
        }
    }
    case ExpiryChecker::NoSuitableSubkey:
        if (result.checkFlags & ExpiryChecker::EncryptionKey) {
            return i18nc("@info", "This certificate cannot be used for encryption.");
        } else {
            return i18nc("@info", "This certificate cannot be used for signing.");
        }
    case ExpiryChecker::InvalidKey:
    case ExpiryChecker::InvalidCheckFlags:
        break; // wrong usage of ExpiryChecker; can be ignored
    case ExpiryChecker::NotNearExpiry:;
    }
    return {};
}

void SignEncryptWidget::updateOp()
{
    const Key sigKey = signKey();
    const std::vector<Key> recp = recipients();

    Operations op = NoOperation;
    if (!sigKey.isNull()) {
        op |= Sign;
    }
    if (!recp.empty() || encryptSymmetric()) {
        op |= Encrypt;
    }
    d->mOp = op;
    Q_EMIT operationChanged(d->mOp);
    Q_EMIT keysChanged();
}

SignEncryptWidget::Operations SignEncryptWidget::currentOp() const
{
    return d->mOp;
}

namespace
{
bool recipientWidgetHasFocus(QWidget *w)
{
    // check if w (or its focus proxy) or a child widget of w has focus
    return w->hasFocus() || w->isAncestorOf(qApp->focusWidget());
}
}

void SignEncryptWidget::Private::recpRemovalRequested(const RecipientWidgets &recipient)
{
    if (!recipient.edit) {
        return;
    }
    if (recipientWidgetHasFocus(recipient.edit) || recipientWidgetHasFocus(recipient.expiryMessage)) {
        const int index = mRecpLayout->indexOf(recipient.edit);
        const auto focusWidget = (index < mRecpLayout->count() - 2) ? //
            mRecpLayout->itemAt(index + 2)->widget()
                                                                    : mRecpLayout->itemAt(mRecpLayout->count() - 3)->widget();
        focusWidget->setFocus();
    }
    mRecpLayout->removeWidget(recipient.expiryMessage);
    mRecpLayout->removeWidget(recipient.edit);
    const auto it = std::find_if(std::begin(mRecpWidgets), std::end(mRecpWidgets), [recipient](const auto &r) {
        return r.edit == recipient.edit;
    });
    mRecpWidgets.erase(it);
    recipient.expiryMessage->deleteLater();
    recipient.edit->deleteLater();
}

void SignEncryptWidget::removeRecipient(const GpgME::Key &key)
{
    for (const auto &recipient : std::as_const(d->mRecpWidgets)) {
        const auto editKey = recipient.edit->key();
        if (key.isNull() && editKey.isNull()) {
            d->recpRemovalRequested(recipient);
            return;
        }
        if (editKey.primaryFingerprint() && key.primaryFingerprint() && !strcmp(editKey.primaryFingerprint(), key.primaryFingerprint())) {
            d->recpRemovalRequested(recipient);
            return;
        }
    }
}

void SignEncryptWidget::removeRecipient(const KeyGroup &group)
{
    for (const auto &recipient : std::as_const(d->mRecpWidgets)) {
        const auto editGroup = recipient.edit->group();
        if (group.isNull() && editGroup.isNull()) {
            d->recpRemovalRequested(recipient);
            return;
        }
        if (editGroup.name() == group.name()) {
            d->recpRemovalRequested(recipient);
            return;
        }
    }
}

bool SignEncryptWidget::encryptSymmetric() const
{
    return d->mSymmetric->isChecked();
}

void SignEncryptWidget::loadKeys()
{
    KConfigGroup keys(KSharedConfig::openConfig(), QStringLiteral("SignEncryptKeys"));
    auto cache = KeyCache::instance();
    d->mSigSelect->setDefaultKey(keys.readEntry("SigningKey", QString()));
    d->mSelfSelect->setDefaultKey(keys.readEntry("EncryptKey", QString()));
}

void SignEncryptWidget::saveOwnKeys() const
{
    KConfigGroup keys(KSharedConfig::openConfig(), QStringLiteral("SignEncryptKeys"));
    auto sigKey = d->mSigSelect->currentKey();
    auto encKey = d->mSelfSelect->currentKey();
    if (!sigKey.isNull()) {
        keys.writeEntry("SigningKey", sigKey.primaryFingerprint());
    }
    if (!encKey.isNull()) {
        keys.writeEntry("EncryptKey", encKey.primaryFingerprint());
    }
}

void SignEncryptWidget::setSigningChecked(bool value)
{
    // d->mSigChk->setChecked(value && !KeyCache::instance()->secretKeys().empty());
}

void SignEncryptWidget::setEncryptionChecked(bool checked)
{
    if (checked) {
        const bool haveSecretKeys = !KeyCache::instance()->secretKeys().empty();
        const bool havePublicKeys = !KeyCache::instance()->keys().empty();
        const bool symmetricOnly = FileOperationsPreferences().symmetricEncryptionOnly();
        // d->mEncSelfChk->setChecked(haveSecretKeys && !symmetricOnly);
        d->mSymmetric->setChecked(symmetricOnly || !havePublicKeys);
    } else {
        // d->mEncSelfChk->setChecked(false);
        d->mSymmetric->setChecked(false);
    }
}

void SignEncryptWidget::setProtocol(GpgME::Protocol proto)
{
    if (d->mCurrentProto == proto) {
        return;
    }
    d->mCurrentProto = proto;
    d->onProtocolChanged();
}

void Kleo::SignEncryptWidget::Private::onProtocolChanged()
{
    auto sigIndex = mSigSelect->currentIndex();
    auto selfEncryptIndex = mSelfSelect->currentIndex();
    auto encryptForOthers = q->recipients().size() > 0;
    mSigSelect->setKeyFilter(std::shared_ptr<KeyFilter>(new SignCertificateFilter(mCurrentProto)));
    mSelfSelect->setKeyFilter(std::shared_ptr<KeyFilter>(new EncryptSelfCertificateFilter(mCurrentProto)));
    const auto encFilter = std::shared_ptr<KeyFilter>(new EncryptCertificateFilter(mCurrentProto));
    for (const auto &widget : std::vector(mRecpWidgets)) {
        recpRemovalRequested(widget);
    }
    addRecipientWidget();
    for (const auto &recipient : std::as_const(mRecpWidgets)) {
        recipient.edit->setKeyFilter(encFilter);
    }
    if (mIsExclusive) {
        mSymmetric->setDisabled(mCurrentProto == GpgME::CMS);
        if (mCurrentProto == GpgME::CMS) {
            if (mSymmetric->isChecked() && mCurrentProto) {
                mSymmetric->setChecked(false);
            }
            if (sigIndex != 0 && selfEncryptIndex == 0 && !encryptForOthers) {
                mSigSelect->setCurrentIndex(1);
            } else {
                mSigSelect->setCurrentIndex(0);
            }
        }
    }

    if (mCurrentProto == GpgME::OpenPGP && sigIndex != 0) {
        mSigSelect->setCurrentIndex(1);
    }

    if (selfEncryptIndex > 0) {
        mSelfSelect->setCurrentIndex(1);
    }
}

static bool recipientIsOkay(const CertificateLineEdit *edit)
{
    if (!edit->isEnabled() || edit->isEmpty()) {
        return true;
    }
    if (!edit->hasAcceptableInput()) {
        return false;
    }
    if (const auto userID = edit->userID(); !userID.isNull()) {
        return Kleo::canBeUsedForEncryption(userID.parent()) && !userID.isBad();
    }
    if (const auto key = edit->key(); !key.isNull()) {
        return Kleo::canBeUsedForEncryption(key);
    }
    if (const auto group = edit->group(); !group.isNull()) {
        return Kleo::all_of(group.keys(), Kleo::canBeUsedForEncryption);
    }
    // we should never reach this point
    return false;
}

bool SignEncryptWidget::isComplete() const
{
    if (currentOp() == NoOperation) {
        return false;
    }
    if ((currentOp() & SignEncryptWidget::Sign) && !Kleo::canBeUsedForSigning(signKey())) {
        return false;
    }
    if (currentOp() & SignEncryptWidget::Encrypt) {
        if (!selfKey().isNull() && !Kleo::canBeUsedForEncryption(selfKey())) {
            return false;
        }
        const bool allOtherRecipientsAreOkay = Kleo::all_of(d->mRecpWidgets, [](const auto &r) {
            return recipientIsOkay(r.edit);
        });
        if (!allOtherRecipientsAreOkay) {
            return false;
        }
    }
    return true;
}

bool SignEncryptWidget::validate()
{
    CertificateLineEdit *firstUnresolvedRecipient = nullptr;
    QStringList unresolvedRecipients;
    for (const auto &recipient : std::as_const(d->mRecpWidgets)) {
        if (recipient.edit->isEnabled() && !recipient.edit->hasAcceptableInput()) {
            if (!firstUnresolvedRecipient) {
                firstUnresolvedRecipient = recipient.edit;
            }
            unresolvedRecipients.push_back(recipient.edit->text().toHtmlEscaped());
        }
    }
    if (!unresolvedRecipients.isEmpty()) {
        KMessageBox::errorList(this,
                               i18n("Could not find a key for the following recipients:"),
                               unresolvedRecipients,
                               i18nc("@title:window", "Failed to find some keys"));
    }
    if (firstUnresolvedRecipient) {
        firstUnresolvedRecipient->setFocus();
    }
    return unresolvedRecipients.isEmpty();
}

void SignEncryptWidget::Private::updateCheckBoxes()
{
    const bool haveSecretKeys = !KeyCache::instance()->secretKeys().empty();
    const bool havePublicKeys = !KeyCache::instance()->keys().empty();
    const bool symmetricOnly = FileOperationsPreferences().symmetricEncryptionOnly();
    mSigChk->setEnabled(haveSecretKeys);
    mEncSelfChk->setEnabled(haveSecretKeys && !symmetricOnly);
    if (symmetricOnly) {
        // mEncSelfChk->setChecked(false);
        mSymmetric->setChecked(true);
    }
}

ExpiryChecker *Kleo::SignEncryptWidget::Private::expiryChecker()
{
    if (!mExpiryChecker) {
        mExpiryChecker.reset(new ExpiryChecker{ExpiryCheckerConfig{}.settings()});
    }
    return mExpiryChecker.get();
}

void SignEncryptWidget::Private::updateExpiryMessages(KMessageWidget *messageWidget, const GpgME::Key &key, ExpiryChecker::CheckFlags flags)
{
    messageWidget->setCloseButtonVisible(false);
    if (!Settings{}.showExpiryNotifications() || key.isNull()) {
        messageWidget->setVisible(false);
    } else {
        const auto result = expiryChecker()->checkKey(key, flags);
        const auto message = expiryMessage(result);
        messageWidget->setText(message);
        messageWidget->setVisible(!message.isEmpty());
    }
}

void SignEncryptWidget::Private::updateAllExpiryMessages()
{
    updateExpiryMessages(mSignKeyExpiryMessage, q->signKey(), ExpiryChecker::OwnSigningKey);
    updateExpiryMessages(mEncryptToSelfKeyExpiryMessage, q->selfKey(), ExpiryChecker::OwnEncryptionKey);
    for (const auto &recipient : std::as_const(mRecpWidgets)) {
        if (recipient.edit->isEnabled()) {
            updateExpiryMessages(recipient.expiryMessage, recipient.edit->key(), ExpiryChecker::EncryptionKey);
        }
    }
}

#include "moc_signencryptwidget.cpp"
