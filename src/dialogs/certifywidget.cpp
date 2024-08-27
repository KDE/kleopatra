/*  dialogs/certifywidget.cpp

    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2019, 2021 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include <config-kleopatra.h>

#include "certifywidget.h"

#include "dialogs/animatedexpander.h"
#include "view/infofield.h"
#include <utils/accessibility.h>
#include <utils/expiration.h>
#include <utils/gui-helper.h>

#include <settings.h>

#include "kleopatra_debug.h"

#include <KConfigGroup>
#include <KDateComboBox>
#include <KLocalizedString>
#include <KMessageBox>
#include <KMessageWidget>
#include <KSeparator>
#include <KSharedConfig>

#include <Libkleo/Algorithm>
#include <Libkleo/DefaultKeyFilter>
#include <Libkleo/Formatting>
#include <Libkleo/KeyCache>
#include <Libkleo/KeyHelpers>
#include <Libkleo/KeySelectionCombo>
#include <Libkleo/Predicates>
#include <Libkleo/TreeWidget>

#include <QGpgME/ChangeOwnerTrustJob>
#include <QGpgME/Protocol>

#include <QAction>
#include <QCheckBox>
#include <QHBoxLayout>
#include <QIcon>
#include <QLabel>
#include <QLineEdit>
#include <QParallelAnimationGroup>
#include <QPropertyAnimation>
#include <QPushButton>
#include <QScrollArea>
#include <QToolButton>
#include <QVBoxLayout>

#include <gpgme++/key.h>

Q_DECLARE_METATYPE(GpgME::UserID)

using namespace Kleo;
using namespace GpgME;

static QDebug operator<<(QDebug s, const GpgME::UserID &userID)
{
    return s << Formatting::prettyUserID(userID);
}

namespace
{

class SecKeyFilter : public DefaultKeyFilter
{
public:
    SecKeyFilter()
        : DefaultKeyFilter()
    {
        setRevoked(DefaultKeyFilter::NotSet);
        setExpired(DefaultKeyFilter::NotSet);
        setHasSecret(DefaultKeyFilter::Set);
        setCanCertify(DefaultKeyFilter::Set);
        setIsOpenPGP(DefaultKeyFilter::Set);
    }

    bool matches(const GpgME::Key &key, Kleo::KeyFilter::MatchContexts contexts) const override
    {
        if (!(availableMatchContexts() & contexts)) {
            return false;
        }
        if (_detail::ByFingerprint<std::equal_to>()(key, mExcludedKey)) {
            return false;
        }
        return DefaultKeyFilter::matches(key, contexts);
    }

    void setExcludedKey(const GpgME::Key &key)
    {
        mExcludedKey = key;
    }

private:
    GpgME::Key mExcludedKey;
};

auto checkBoxSize(const QCheckBox *checkBox)
{
    QStyleOptionButton opt;
    return checkBox->style()->sizeFromContents(QStyle::CT_CheckBox, &opt, QSize(), checkBox);
}

class TreeWidgetInternal : public TreeWidget
{
    Q_OBJECT
public:
    using TreeWidget::TreeWidget;

protected:
    bool edit(const QModelIndex &index, EditTrigger trigger, QEvent *event) override
    {
        if (event && event->type() == QEvent::KeyPress) {
            const auto *const keyEvent = static_cast<QKeyEvent *>(event);
            if (keyEvent->key() == Qt::Key_Space || keyEvent->key() == Qt::Key_Select) {
                // toggle checked state regardless of the index's column
                return TreeWidget::edit(index.siblingAtColumn(0), trigger, event);
            }
        }
        return TreeWidget::edit(index, trigger, event);
    }
};

struct UserIDCheckState {
    GpgME::UserID userId;
    Qt::CheckState checkState;
};
}

class CertifyWidget::Private
{
public:
    enum Role { UserIdRole = Qt::UserRole };
    enum Mode {
        SingleCertification,
        BulkCertification,
    };
    enum TagsState {
        TagsMustBeChecked,
        TagsLoading,
        TagsLoaded,
    };

    Private(CertifyWidget *qq)
        : q{qq}
    {
        auto mainLay = new QVBoxLayout{q};

        {
            mInfoLabel = new QLabel{i18n("Verify the fingerprint, mark the user IDs you want to certify, "
                                         "and select the key you want to certify the user IDs with.<br>"
                                         "<i>Note: Only the fingerprint clearly identifies the key and its owner.</i>"),
                                    q};
            mInfoLabel->setWordWrap(true);
            labelHelper.addLabel(mInfoLabel);
            mainLay->addWidget(mInfoLabel);
        }

        mainLay->addWidget(new KSeparator{Qt::Horizontal, q});

        {
            auto grid = new QGridLayout;
            grid->setColumnStretch(1, 1);
            int row = -1;

            row++;
            mFprField = std::make_unique<InfoField>(i18n("Fingerprint:"), q);
            grid->addWidget(mFprField->label(), row, 0);
            grid->addLayout(mFprField->layout(), row, 1);

            row++;
            auto label = new QLabel{i18n("Certify with:"), q};
            mSecKeySelect = new KeySelectionCombo{/* secretOnly= */ true, q};
            mSecKeySelect->setKeyFilter(std::make_shared<SecKeyFilter>());
            label->setBuddy(mSecKeySelect);
            grid->addWidget(label, row, 0);
            grid->addWidget(mSecKeySelect);

            mainLay->addLayout(grid);
        }

        mMissingOwnerTrustInfo = new KMessageWidget{q};
        mSetOwnerTrustAction = new QAction{q};
        mSetOwnerTrustAction->setText(i18nc("@action:button", "Set Owner Trust"));
        mSetOwnerTrustAction->setToolTip(i18nc("@info:tooltip",
                                               "Click to set the trust level of the selected certification key to ultimate trust. "
                                               "This is what you usually want to do for your own keys."));
        connect(mSetOwnerTrustAction, &QAction::triggered, q, [this]() {
            setOwnerTrust();
        });
        mMissingOwnerTrustInfo->addAction(mSetOwnerTrustAction);
        mMissingOwnerTrustInfo->setVisible(false);

        mainLay->addWidget(mMissingOwnerTrustInfo);

        mainLay->addWidget(new KSeparator{Qt::Horizontal, q});

        mBadCertificatesInfo = new KMessageWidget{q};
        mBadCertificatesInfo->setMessageType(KMessageWidget::Warning);
        mBadCertificatesInfo->setIcon(QIcon::fromTheme(QStringLiteral("data-warning"), QIcon::fromTheme(QStringLiteral("dialog-warning"))));
        mBadCertificatesInfo->setText(i18nc("@info", "One or more certificates cannot be certified."));
        mBadCertificatesInfo->setCloseButtonVisible(false);
        mBadCertificatesInfo->setVisible(false);
        mainLay->addWidget(mBadCertificatesInfo);

        userIdListView = new TreeWidget{q};
        userIdListView->setAccessibleName(i18n("User IDs"));
        userIdListView->setEditTriggers(QAbstractItemView::NoEditTriggers);
        userIdListView->setSelectionMode(QAbstractItemView::SingleSelection);
        userIdListView->setRootIsDecorated(false);
        userIdListView->setUniformRowHeights(true);
        userIdListView->setAllColumnsShowFocus(false);
        userIdListView->setHeaderHidden(true);
        userIdListView->setHeaderLabels({i18nc("@title:column", "User ID")});
        mainLay->addWidget(userIdListView, 1);

        // Setup the advanced area
        mAdvancedOptionsExpander = new AnimatedExpander{i18n("Advanced"), i18n("Show advanced options"), q};
        mainLay->addWidget(mAdvancedOptionsExpander);

        auto advLay = new QVBoxLayout;

        mExportCB = new QCheckBox{q};
        mExportCB->setText(i18n("Certify for everyone to see (exportable)"));
        mExportCB->setToolTip(xi18nc("@info:tooltip",
                                     "Check this option, if you want to share your certifications with others. "
                                     "If you just want to mark certificates as certified for yourself, then you can uncheck it."));
        advLay->addWidget(mExportCB);

        {
            auto layout = new QHBoxLayout;

            mPublishCB = new QCheckBox{q};
            mPublishCB->setText(i18n("Publish on keyserver afterwards"));
            mPublishCB->setToolTip(xi18nc("@info:tooltip",
                                          "Check this option, if you want to upload your certifications to a certificate "
                                          "directory after successful certification."));
            mPublishCB->setEnabled(mExportCB->isChecked());

            layout->addSpacing(checkBoxSize(mExportCB).width());
            layout->addWidget(mPublishCB);

            advLay->addLayout(layout);
        }

        {
            auto tagsLay = new QHBoxLayout;

            auto label = new QLabel{i18n("Tags:"), q};
            mTagsLE = new QLineEdit{q};
            label->setBuddy(mTagsLE);

            const auto tooltip = i18n("You can use this to add additional info to a certification.") + QStringLiteral("<br/><br/>")
                + i18n("Tags created by anyone with full certification trust "
                       "are shown in the keylist and can be searched.");
            label->setToolTip(tooltip);
            mTagsLE->setToolTip(tooltip);

            tagsLay->addWidget(label);
            tagsLay->addWidget(mTagsLE, 1);

            advLay->addLayout(tagsLay);
        }

        {
            auto layout = new QHBoxLayout;

            mExpirationCheckBox = new QCheckBox{q};
            mExpirationCheckBox->setText(i18n("Expiration:"));

            mExpirationDateEdit = new KDateComboBox{q};
            Kleo::setUpExpirationDateComboBox(mExpirationDateEdit, {QDate::currentDate().addDays(1), QDate{}});
            mExpirationDateEdit->setDate(Kleo::defaultExpirationDate(ExpirationOnUnlimitedValidity::InternalDefaultExpiration));
            mExpirationDateEdit->setEnabled(mExpirationCheckBox->isChecked());

            const auto tooltip = i18n("You can use this to set an expiration date for a certification.") + QStringLiteral("<br/><br/>")
                + i18n("By setting an expiration date, you can limit the validity of "
                       "your certification to a certain amount of time. Once the expiration "
                       "date has passed, your certification is no longer valid.");
            mExpirationCheckBox->setToolTip(tooltip);
            mExpirationDateEdit->setToolTip(tooltip);

            layout->addWidget(mExpirationCheckBox);
            layout->addWidget(mExpirationDateEdit, 1);

            advLay->addLayout(layout);
        }

        {
            mTrustSignatureCB = new QCheckBox{q};
            mTrustSignatureWidgets.addWidget(mTrustSignatureCB);
            mTrustSignatureCB->setText(i18n("Certify as trusted introducer"));
            const auto tooltip = i18n("You can use this to certify a trusted introducer for a domain.") + QStringLiteral("<br/><br/>")
                + i18n("All certificates with email addresses belonging to the domain "
                       "that have been certified by the trusted introducer are treated "
                       "as certified, i.e. a trusted introducer acts as a kind of "
                       "intermediate CA for a domain.");
            mTrustSignatureCB->setToolTip(tooltip);

            advLay->addWidget(mTrustSignatureCB);
        }
        {
            auto layout = new QHBoxLayout;

            auto label = new QLabel{i18n("Domain:"), q};
            mTrustSignatureWidgets.addWidget(label);

            mTrustSignatureDomainLE = new QLineEdit{q};
            mTrustSignatureWidgets.addWidget(mTrustSignatureDomainLE);
            mTrustSignatureDomainLE->setEnabled(mTrustSignatureCB->isChecked());
            label->setBuddy(mTrustSignatureDomainLE);

            layout->addSpacing(checkBoxSize(mTrustSignatureCB).width());
            layout->addWidget(label);
            layout->addWidget(mTrustSignatureDomainLE);

            advLay->addLayout(layout);
        }

        mAdvancedOptionsExpander->setContentLayout(advLay);

        connect(userIdListView, &QTreeWidget::itemChanged, q, [this](auto item, auto) {
            onItemChanged(item);
        });

        connect(mExportCB, &QCheckBox::toggled, [this](bool on) {
            mPublishCB->setEnabled(on);
        });

        connect(mSecKeySelect, &KeySelectionCombo::currentKeyChanged, [this](const GpgME::Key &) {
            updateSelectedUserIds();
            updateTags();
            checkOwnerTrust();
            Q_EMIT q->changed();
        });

        connect(mExpirationCheckBox, &QCheckBox::toggled, q, [this](bool checked) {
            mExpirationDateEdit->setEnabled(checked);
            Q_EMIT q->changed();
        });
        connect(mExpirationDateEdit, &KDateComboBox::dateChanged, q, &CertifyWidget::changed);

        connect(mTrustSignatureCB, &QCheckBox::toggled, q, [this](bool on) {
            mTrustSignatureDomainLE->setEnabled(on);
            Q_EMIT q->changed();
        });
        connect(mTrustSignatureDomainLE, &QLineEdit::textChanged, q, &CertifyWidget::changed);

        loadConfig(true);
    }

    ~Private() = default;

    void loadConfig(bool loadAll = false)
    {
        const KConfigGroup conf(KSharedConfig::openConfig(), "CertifySettings");

        if (loadAll) {
            const Settings settings;
            mExpirationCheckBox->setChecked(settings.certificationValidityInDays() > 0);
            if (settings.certificationValidityInDays() > 0) {
                const QDate expirationDate = QDate::currentDate().addDays(settings.certificationValidityInDays());
                mExpirationDateEdit->setDate(expirationDate > mExpirationDateEdit->maximumDate() //
                                                 ? mExpirationDateEdit->maximumDate() //
                                                 : expirationDate);
            }

            mSecKeySelect->setDefaultKey(conf.readEntry("LastKey", QString()));
        }

        switch (mMode) {
        case SingleCertification: {
            mExportCB->setChecked(conf.readEntry("ExportCheckState", false));
            mPublishCB->setChecked(conf.readEntry("PublishCheckState", false));
            mAdvancedOptionsExpander->setExpanded(conf.readEntry("AdvancedOptionsExpanded", false));
            break;
        }
        case BulkCertification: {
            mExportCB->setChecked(conf.readEntry("BulkExportCheckState", true));
            mPublishCB->setChecked(conf.readEntry("BulkPublishCheckState", false));
            mAdvancedOptionsExpander->setExpanded(conf.readEntry("BulkAdvancedOptionsExpanded", true));
            break;
        }
        }
    }

    void saveConfig()
    {
        KConfigGroup conf{KSharedConfig::openConfig(), "CertifySettings"};
        if (!secKey().isNull()) {
            conf.writeEntry("LastKey", secKey().primaryFingerprint());
        }
        switch (mMode) {
        case SingleCertification: {
            conf.writeEntry("ExportCheckState", mExportCB->isChecked());
            conf.writeEntry("PublishCheckState", mPublishCB->isChecked());
            conf.writeEntry("AdvancedOptionsExpanded", mAdvancedOptionsExpander->isExpanded());
            break;
        }
        case BulkCertification: {
            conf.writeEntry("BulkExportCheckState", mExportCB->isChecked());
            conf.writeEntry("BulkPublishCheckState", mPublishCB->isChecked());
            conf.writeEntry("BulkAdvancedOptionsExpanded", mAdvancedOptionsExpander->isExpanded());
            break;
        }
        }
        conf.sync();
    }

    void setMode(Mode mode)
    {
        mMode = mode;
        switch (mMode) {
        case SingleCertification:
            break;
        case BulkCertification: {
            mInfoLabel->setText(i18nc("@info",
                                      "Verify the fingerprints, mark the user IDs you want to certify, "
                                      "and select the certificate you want to certify the user IDs with.<br>"
                                      "<i>Note: Only the fingerprints clearly identify the certificate and its owner.</i>"));
            mFprField->setVisible(false);
            mTrustSignatureWidgets.setVisible(false);
            break;
        }
        }
        loadConfig();
    }

    void setUpUserIdList(const std::vector<GpgME::UserID> &uids = {})
    {
        userIdListView->clear();
        if (mMode == SingleCertification) {
            userIdListView->setColumnCount(1);
            userIdListView->setHeaderHidden(true);
            // set header labels for accessibility tools to overwrite the default "1"
            userIdListView->setHeaderLabels({i18nc("@title:column", "User ID")});
            for (const auto &uid : uids) {
                if (uid.isInvalid() || Kleo::isRevokedOrExpired(uid)) {
                    // Skip user IDs that cannot really be certified.
                    continue;
                }
                auto item = new QTreeWidgetItem;
                item->setData(0, UserIdRole, QVariant::fromValue(uid));
                item->setData(0, Qt::DisplayRole, Kleo::Formatting::prettyUserID(uid));
                item->setFlags(Qt::ItemIsSelectable | Qt::ItemIsUserCheckable | Qt::ItemIsEnabled);
                item->setCheckState(0, Qt::Checked);
                userIdListView->addTopLevelItem(item);
            }
        } else {
            const QStringList headers = {i18nc("@title:column", "User ID"), i18nc("@title:column", "Fingerprint")};
            userIdListView->setColumnCount(headers.count());
            userIdListView->setHeaderHidden(false);
            userIdListView->setHeaderLabels(headers);
            for (const auto &key : mKeys) {
                const auto &uid = key.userID(0);
                auto item = new QTreeWidgetItem;
                item->setData(0, UserIdRole, QVariant::fromValue(uid));
                item->setData(0, Qt::DisplayRole, Kleo::Formatting::prettyUserID(uid));
                item->setData(1, Qt::DisplayRole, Kleo::Formatting::prettyID(key.primaryFingerprint()));
                item->setData(1, Qt::AccessibleTextRole, Kleo::Formatting::accessibleHexID(key.primaryFingerprint()));

                if ((key.protocol() != OpenPGP) || uid.isInvalid() || Kleo::isRevokedOrExpired(uid)) {
                    item->setFlags(Qt::NoItemFlags);
                    item->setCheckState(0, Qt::Unchecked);
                    if (key.protocol() == CMS) {
                        item->setData(0, Qt::ToolTipRole, i18nc("@info:tooltip", "S/MIME certificates cannot be certified."));
                        item->setData(1, Qt::ToolTipRole, i18nc("@info:tooltip", "S/MIME certificates cannot be certified."));
                    } else {
                        item->setData(0, Qt::ToolTipRole, i18nc("@info:tooltip", "Expired or revoked certificates cannot be certified."));
                        item->setData(1, Qt::ToolTipRole, i18nc("@info:tooltip", "Expired or revoked certificates cannot be certified."));
                    }
                } else {
                    item->setFlags(Qt::ItemIsSelectable | Qt::ItemIsUserCheckable | Qt::ItemIsEnabled);
                    item->setCheckState(0, Qt::Checked);
                }
                userIdListView->addTopLevelItem(item);
            }
            userIdListView->sortItems(0, Qt::AscendingOrder);
            userIdListView->resizeToContentsLimited();
        }
    }

    void updateSelectedUserIds()
    {
        if (mMode == SingleCertification) {
            return;
        }
        if (userIdListView->topLevelItemCount() == 0) {
            return;
        }

        // restore check state of primary user ID of previous certification key
        if (!mCertificationKey.isNull()) {
            for (int i = 0, end = userIdListView->topLevelItemCount(); i < end; ++i) {
                const auto uidItem = userIdListView->topLevelItem(i);
                const auto itemUserId = getUserId(uidItem);
                if (userIDBelongsToKey(itemUserId, mCertificationKey)) {
                    uidItem->setCheckState(0, mCertificationKeyUserIDCheckState);
                    uidItem->setFlags(Qt::ItemIsSelectable | Qt::ItemIsUserCheckable | Qt::ItemIsEnabled);
                    break; // we only show the primary user IDs
                }
            }
        }

        mCertificationKey = mSecKeySelect->currentKey();

        // save and unset check state of primary user ID of current certification key
        if (!mCertificationKey.isNull()) {
            for (int i = 0, end = userIdListView->topLevelItemCount(); i < end; ++i) {
                const auto uidItem = userIdListView->topLevelItem(i);
                const auto itemUserId = getUserId(uidItem);
                if (userIDBelongsToKey(itemUserId, mCertificationKey)) {
                    mCertificationKeyUserIDCheckState = uidItem->checkState(0);
                    if (mCertificationKeyUserIDCheckState) {
                        uidItem->setCheckState(0, Qt::Unchecked);
                    }
                    uidItem->setFlags(Qt::ItemIsSelectable);
                    break; // we only show the primary user IDs
                }
            }
        }
    }

    void updateTags()
    {
        struct ItemAndRemark {
            QTreeWidgetItem *item;
            QString remark;
        };

        if (mTagsState != TagsLoaded) {
            return;
        }
        if (mTagsLE->isModified()) {
            return;
        }
        GpgME::Key remarkKey = mSecKeySelect->currentKey();

        if (!remarkKey.isNull()) {
            std::vector<ItemAndRemark> itemsAndRemarks;
            // first choose the remark we want to prefill the Tags field with
            QString remark;
            for (int i = 0, end = userIdListView->topLevelItemCount(); i < end; ++i) {
                const auto item = userIdListView->topLevelItem(i);
                if (item->isDisabled()) {
                    continue;
                }
                const auto uid = getUserId(item);
                GpgME::Error err;
                const char *c_remark = uid.remark(remarkKey, err);
                const QString itemRemark = (!err && c_remark) ? QString::fromUtf8(c_remark) : QString{};
                if (!itemRemark.isEmpty() && (itemRemark != remark)) {
                    if (!remark.isEmpty()) {
                        qCDebug(KLEOPATRA_LOG) << "Different remarks on user IDs. Taking last.";
                    }
                    remark = itemRemark;
                }
                itemsAndRemarks.push_back({item, itemRemark});
            }
            // then select the user IDs with the chosen remark; this prevents overwriting existing
            // different remarks on the other user IDs (as long as the user doesn't select any of
            // the unselected user IDs with a different remark)
            if (!remark.isEmpty()) {
                for (const auto &[item, itemRemark] : itemsAndRemarks) {
                    item->setCheckState(0, itemRemark == remark ? Qt::Checked : Qt::Unchecked);
                }
            }
            mTagsLE->setText(remark);
        }
    }

    void updateTrustSignatureDomain()
    {
        if (mMode == SingleCertification) {
            if (mTrustSignatureDomainLE->text().isEmpty() && certificate().numUserIDs() == 1) {
                // try to guess the domain to use for the trust signature
                const auto address = certificate().userID(0).addrSpec();
                const auto atPos = address.find('@');
                if (atPos != std::string::npos) {
                    const auto domain = address.substr(atPos + 1);
                    mTrustSignatureDomainLE->setText(QString::fromUtf8(domain.c_str(), domain.size()));
                }
            }
        }
    }

    void loadAllTags()
    {
        const auto keyWithoutTags = std::find_if(mKeys.cbegin(), mKeys.cend(), [](const auto &key) {
            return (key.protocol() == GpgME::OpenPGP) && !(key.keyListMode() & GpgME::SignatureNotations);
        });
        const auto indexOfKeyWithoutTags = std::distance(mKeys.cbegin(), keyWithoutTags);
        if (indexOfKeyWithoutTags < signed(mKeys.size())) {
            auto loadTags = [this, indexOfKeyWithoutTags]() {
                Q_ASSERT(indexOfKeyWithoutTags < signed(mKeys.size()));
                // call update() on the reference to the vector element because it swaps key with the updated key
                mKeys[indexOfKeyWithoutTags].update();
                loadAllTags();
            };
            QMetaObject::invokeMethod(q, loadTags, Qt::QueuedConnection);
            return;
        }
        mTagsState = TagsLoaded;
        QMetaObject::invokeMethod(
            q,
            [this]() {
                setUpWidget();
            },
            Qt::QueuedConnection);
    }

    bool ensureTagsLoaded()
    {
        Q_ASSERT(mTagsState != TagsLoading);
        if (mTagsState == TagsLoaded) {
            return true;
        }

        const auto allTagsAreLoaded = std::ranges::all_of(mKeys, [](const auto &key) {
            return (key.protocol() != GpgME::OpenPGP) || (key.keyListMode() & GpgME::SignatureNotations);
        });
        if (allTagsAreLoaded) {
            mTagsState = TagsLoaded;
        } else {
            mTagsState = TagsLoading;
            QMetaObject::invokeMethod(
                q,
                [this]() {
                    loadAllTags();
                },
                Qt::QueuedConnection);
        }
        return mTagsState == TagsLoaded;
    }

    void setUpWidget()
    {
        if (!ensureTagsLoaded()) {
            return;
        }
        if (mMode == SingleCertification) {
            const auto key = certificate();
            mFprField->setValue(QStringLiteral("<b>") + Formatting::prettyID(key.primaryFingerprint()) + QStringLiteral("</b>"),
                                Formatting::accessibleHexID(key.primaryFingerprint()));
            setUpUserIdList(mUserIds.empty() ? key.userIDs() : mUserIds);

            auto keyFilter = std::make_shared<SecKeyFilter>();
            keyFilter->setExcludedKey(key);
            mSecKeySelect->setKeyFilter(keyFilter);

            updateTrustSignatureDomain();
        } else {
            // check for certificates that cannot be certified
            const auto haveBadCertificates = std::ranges::any_of(mKeys, [](const auto &key) {
                const auto &uid = key.userID(0);
                return (key.protocol() != OpenPGP) || uid.isInvalid() || Kleo::isRevokedOrExpired(uid);
            });
            if (haveBadCertificates) {
                mBadCertificatesInfo->animatedShow();
            }

            setUpUserIdList();
        }
        updateTags();
        updateSelectedUserIds();
        Q_EMIT q->changed();
    }

    GpgME::Key certificate() const
    {
        Q_ASSERT(mMode == SingleCertification);
        return !mKeys.empty() ? mKeys.front() : Key{};
    }

    void setCertificates(const std::vector<GpgME::Key> &keys, const std::vector<GpgME::UserID> &uids)
    {
        mKeys = keys;
        mUserIds = uids;
        mTagsState = TagsMustBeChecked;
        setUpWidget();
    }

    std::vector<GpgME::Key> certificates() const
    {
        Q_ASSERT(mMode != SingleCertification);
        return mKeys;
    }

    GpgME::Key secKey() const
    {
        return mSecKeySelect->currentKey();
    }

    GpgME::UserID getUserId(const QTreeWidgetItem *item) const
    {
        return item ? item->data(0, UserIdRole).value<UserID>() : UserID{};
    }

    void selectUserIDs(const std::vector<GpgME::UserID> &uids)
    {
        for (int i = 0, end = userIdListView->topLevelItemCount(); i < end; ++i) {
            const auto uidItem = userIdListView->topLevelItem(i);
            const auto itemUserId = getUserId(uidItem);
            const bool userIdIsInList = std::ranges::any_of(uids, [itemUserId](const auto &uid) {
                return Kleo::userIDsAreEqual(itemUserId, uid);
            });
            uidItem->setCheckState(0, userIdIsInList ? Qt::Checked : Qt::Unchecked);
        }
    }

    std::vector<GpgME::UserID> selectedUserIDs() const
    {
        std::vector<GpgME::UserID> userIds;
        userIds.reserve(userIdListView->topLevelItemCount());
        for (int i = 0, end = userIdListView->topLevelItemCount(); i < end; ++i) {
            const auto *const uidItem = userIdListView->topLevelItem(i);
            if (uidItem->checkState(0) == Qt::Checked) {
                userIds.push_back(getUserId(uidItem));
            }
        }
        qCDebug(KLEOPATRA_LOG) << "Checked user IDs:" << userIds;
        return userIds;
    }

    bool exportableSelected() const
    {
        return mExportCB->isChecked();
    }

    bool publishSelected() const
    {
        return mPublishCB->isChecked();
    }

    QString tags() const
    {
        return mTagsLE->text().trimmed();
    }

    bool isValid() const
    {
        static const QRegularExpression domainNameRegExp{QStringLiteral(R"(^\s*((xn--)?[a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,}\s*$)"),
                                                         QRegularExpression::CaseInsensitiveOption};

        if (mTagsState != TagsLoaded) {
            return false;
        }
        // do not accept null keys
        if (mKeys.empty() || mSecKeySelect->currentKey().isNull()) {
            return false;
        }
        // do not accept empty list of user IDs
        const auto userIds = selectedUserIDs();
        if (userIds.empty()) {
            return false;
        }
        // do not accept if any of the selected user IDs belongs to the certification key
        const auto certificationKey = mSecKeySelect->currentKey();
        const auto userIdToCertifyBelongsToCertificationKey = std::any_of(userIds.cbegin(), userIds.cend(), [certificationKey](const auto &userId) {
            return Kleo::userIDBelongsToKey(userId, certificationKey);
        });
        if (userIdToCertifyBelongsToCertificationKey) {
            return false;
        }
        if (mExpirationCheckBox->isChecked() && !mExpirationDateEdit->isValid()) {
            return false;
        }
        if (mTrustSignatureCB->isChecked() && !domainNameRegExp.match(mTrustSignatureDomainLE->text()).hasMatch()) {
            return false;
        }
        return true;
    }

    void checkOwnerTrust()
    {
        const auto secretKey = secKey();
        if (secretKey.ownerTrust() != GpgME::Key::Ultimate) {
            mMissingOwnerTrustInfo->setMessageType(KMessageWidget::Information);
            mMissingOwnerTrustInfo->setIcon(QIcon::fromTheme(QStringLiteral("question")));
            mMissingOwnerTrustInfo->setText(i18n("Is this your own key?"));
            mSetOwnerTrustAction->setEnabled(true);
            mMissingOwnerTrustInfo->animatedShow();
        } else {
            mMissingOwnerTrustInfo->animatedHide();
        }
    }

    void setOwnerTrust()
    {
        mSetOwnerTrustAction->setEnabled(false);
        QGpgME::ChangeOwnerTrustJob *const j = QGpgME::openpgp()->changeOwnerTrustJob();
        connect(j, &QGpgME::ChangeOwnerTrustJob::result, q, [this](const GpgME::Error &err) {
            if (err) {
                KMessageBox::error(q,
                                   i18n("<p>Changing the certification trust of the key <b>%1</b> failed:</p><p>%2</p>",
                                        Formatting::formatForComboBox(secKey()),
                                        Formatting::errorAsString(err)),
                                   i18n("Certification Trust Change Failed"));
            }
            if (err || err.isCanceled()) {
                mSetOwnerTrustAction->setEnabled(true);
            } else {
                mMissingOwnerTrustInfo->setMessageType(KMessageWidget::Positive);
                mMissingOwnerTrustInfo->setIcon(QIcon::fromTheme(QStringLiteral("checkmark")));
                mMissingOwnerTrustInfo->setText(i18n("Owner trust set successfully."));
            }
        });
        j->start(secKey(), GpgME::Key::Ultimate);
    }

    void onItemChanged(QTreeWidgetItem *item)
    {
        Q_EMIT q->changed();

#ifndef QT_NO_ACCESSIBILITY
        if (item) {
            // assume that the checked state changed
            QAccessible::State st;
            st.checked = true;
            QAccessibleStateChangeEvent e(userIdListView, st);
            e.setChild(userIdListView->indexOfTopLevelItem(item));
            QAccessible::updateAccessibility(&e);
        }
#endif
    }

public:
    CertifyWidget *const q;
    QLabel *mInfoLabel = nullptr;
    std::unique_ptr<InfoField> mFprField;
    KeySelectionCombo *mSecKeySelect = nullptr;
    KMessageWidget *mMissingOwnerTrustInfo = nullptr;
    KMessageWidget *mBadCertificatesInfo = nullptr;
    TreeWidget *userIdListView = nullptr;
    AnimatedExpander *mAdvancedOptionsExpander = nullptr;
    QCheckBox *mExportCB = nullptr;
    QCheckBox *mPublishCB = nullptr;
    QLineEdit *mTagsLE = nullptr;
    BulkStateChanger mTrustSignatureWidgets;
    QCheckBox *mTrustSignatureCB = nullptr;
    QLineEdit *mTrustSignatureDomainLE = nullptr;
    QCheckBox *mExpirationCheckBox = nullptr;
    KDateComboBox *mExpirationDateEdit = nullptr;
    QAction *mSetOwnerTrustAction = nullptr;

    LabelHelper labelHelper;

    Mode mMode = SingleCertification;
    std::vector<GpgME::Key> mKeys;
    std::vector<GpgME::UserID> mUserIds;
    TagsState mTagsState = TagsMustBeChecked;

    GpgME::Key mCertificationKey;
    Qt::CheckState mCertificationKeyUserIDCheckState;
};

CertifyWidget::CertifyWidget(QWidget *parent)
    : QWidget{parent}
    , d{std::make_unique<Private>(this)}
{
}

Kleo::CertifyWidget::~CertifyWidget() = default;

void CertifyWidget::setCertificate(const GpgME::Key &key, const std::vector<GpgME::UserID> &uids)
{
    Q_ASSERT(!key.isNull());
    d->setMode(Private::SingleCertification);
    d->setCertificates({key}, uids);
}

GpgME::Key CertifyWidget::certificate() const
{
    return d->certificate();
}

void CertifyWidget::setCertificates(const std::vector<GpgME::Key> &keys)
{
    d->setMode(Private::BulkCertification);
    d->setCertificates(keys, {});
}

std::vector<GpgME::Key> CertifyWidget::certificates() const
{
    return d->certificates();
}

void CertifyWidget::selectUserIDs(const std::vector<GpgME::UserID> &uids)
{
    d->selectUserIDs(uids);
}

std::vector<GpgME::UserID> CertifyWidget::selectedUserIDs() const
{
    return d->selectedUserIDs();
}

GpgME::Key CertifyWidget::secKey() const
{
    return d->secKey();
}

bool CertifyWidget::exportableSelected() const
{
    return d->exportableSelected();
}

QString CertifyWidget::tags() const
{
    return d->tags();
}

bool CertifyWidget::publishSelected() const
{
    return d->publishSelected();
}

bool CertifyWidget::trustSignatureSelected() const
{
    return d->mTrustSignatureCB->isChecked();
}

QString CertifyWidget::trustSignatureDomain() const
{
    return d->mTrustSignatureDomainLE->text().trimmed();
}

QDate CertifyWidget::expirationDate() const
{
    return d->mExpirationCheckBox->isChecked() ? d->mExpirationDateEdit->date() : QDate{};
}

bool CertifyWidget::isValid() const
{
    return d->isValid();
}

void CertifyWidget::saveState() const
{
    d->saveConfig();
}

#include "certifywidget.moc"
