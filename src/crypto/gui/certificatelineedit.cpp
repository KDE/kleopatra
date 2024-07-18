/*  crypto/gui/certificatelineedit.cpp

    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2016 Bundesamt für Sicherheit in der Informationstechnik
    SPDX-FileContributor: Intevation GmbH
    SPDX-FileCopyrightText: 2021, 2022 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include "certificatelineedit.h"

#include "commands/detailscommand.h"
#include "dialogs/groupdetailsdialog.h"
#include "utils/accessibility.h"
#include "view/errorlabel.h"

#include <QAccessible>
#include <QAction>
#include <QCompleter>
#include <QPushButton>
#include <QSignalBlocker>

#include "kleopatra_debug.h"

#include <Libkleo/Debug>
#include <Libkleo/Formatting>
#include <Libkleo/KeyCache>
#include <Libkleo/KeyFilter>
#include <Libkleo/KeyGroup>
#include <Libkleo/KeyList>
#include <Libkleo/KeyListModel>
#include <Libkleo/KeyListSortFilterProxyModel>
#include <Libkleo/UserIDProxyModel>

#include <KLocalizedString>

#include <gpgme++/key.h>
#include <gpgme++/keylistresult.h>

#include <QGpgME/KeyListJob>
#include <QGpgME/Protocol>

#include <QHBoxLayout>
#include <QLineEdit>
#include <QMenu>
#include <QToolButton>

using namespace Kleo;
using namespace GpgME;

Q_DECLARE_METATYPE(GpgME::Key)
Q_DECLARE_METATYPE(GpgME::UserID)
Q_DECLARE_METATYPE(KeyGroup)

static QStringList s_lookedUpKeys;

namespace
{
class CompletionProxyModel : public KeyListSortFilterProxyModel
{
    Q_OBJECT

public:
    CompletionProxyModel(QObject *parent = nullptr)
        : KeyListSortFilterProxyModel(parent)
    {
    }

    int columnCount(const QModelIndex &parent = QModelIndex()) const override
    {
        Q_UNUSED(parent)
        // pretend that there is only one column to workaround a bug in
        // QAccessibleTable which provides the accessibility interface for the
        // completion pop-up
        return 1;
    }

    QVariant data(const QModelIndex &idx, int role) const override
    {
        if (!idx.isValid()) {
            return QVariant();
        }

        switch (role) {
        case Qt::DecorationRole: {
            const auto key = KeyListSortFilterProxyModel::data(idx, KeyList::KeyRole).value<GpgME::Key>();
            if (!key.isNull()) {
                return Kleo::Formatting::iconForUid(key.userID(0));
            }

            const auto userID = KeyListSortFilterProxyModel::data(idx, KeyList::UserIDRole).value<GpgME::UserID>();
            if (!userID.isNull()) {
                return Kleo::Formatting::iconForUid(userID);
            }

            const auto group = KeyListSortFilterProxyModel::data(idx, KeyList::GroupRole).value<KeyGroup>();
            if (!group.isNull()) {
                return QIcon::fromTheme(QStringLiteral("group"));
            }

            Q_ASSERT(!key.isNull() || !userID.isNull() || !group.isNull());
            return QVariant();
        }
        default:
            return KeyListSortFilterProxyModel::data(index(idx.row(), KeyList::Summary), role);
        }
    }

private:
    bool lessThan(const QModelIndex &left, const QModelIndex &right) const override
    {
        const auto leftKey = sourceModel()->data(left, KeyList::KeyRole).value<GpgME::Key>();
        const auto leftGroup = leftKey.isNull() ? sourceModel()->data(left, KeyList::GroupRole).value<KeyGroup>() : KeyGroup{};
        const auto leftUserID = sourceModel()->data(left, KeyList::UserIDRole).value<GpgME::UserID>();
        const auto rightUserID = sourceModel()->data(right, KeyList::UserIDRole).value<GpgME::UserID>();
        const auto rightKey = sourceModel()->data(right, KeyList::KeyRole).value<GpgME::Key>();
        const auto rightGroup = rightKey.isNull() ? sourceModel()->data(right, KeyList::GroupRole).value<KeyGroup>() : KeyGroup{};

        // shouldn't happen, but still put null entries at the end
        if (leftKey.isNull() && leftUserID.isNull() && leftGroup.isNull()) {
            return false;
        }
        if (rightKey.isNull() && rightUserID.isNull() && rightGroup.isNull()) {
            return true;
        }

        // first sort by the displayed name and/or email address
        const auto leftNameAndOrEmail = leftGroup.isNull()
            ? (leftKey.isNull() ? Formatting::nameAndEmailForSummaryLine(leftUserID) : Formatting::nameAndEmailForSummaryLine(leftKey))
            : leftGroup.name();
        const auto rightNameAndOrEmail = rightGroup.isNull()
            ? (rightKey.isNull() ? Formatting::nameAndEmailForSummaryLine(rightUserID) : Formatting::nameAndEmailForSummaryLine(rightKey))
            : rightGroup.name();
        const int cmp = QString::localeAwareCompare(leftNameAndOrEmail, rightNameAndOrEmail);
        if (cmp) {
            return cmp < 0;
        }
        // then sort groups before certificates
        if (!leftGroup.isNull() && (!rightKey.isNull() || !rightUserID.isNull())) {
            return true; // left is group, right is certificate
        }
        if ((!leftKey.isNull() || !rightKey.isNull()) && !rightGroup.isNull()) {
            return false; // left is certificate, right is group
        }

        // if both are groups (with identical names) sort them by their ID
        if (!leftGroup.isNull() && !rightGroup.isNull()) {
            return leftGroup.id() < rightGroup.id();
        }

        // sort certificates with same name/email by validity and creation time
        const auto lUid = leftUserID.isNull() ? leftKey.userID(0) : leftUserID;
        const auto rUid = rightUserID.isNull() ? rightKey.userID(0) : rightUserID;
        if (lUid.validity() != rUid.validity()) {
            return lUid.validity() > rUid.validity();
        }

        /* Both have the same validity, check which one is newer. */
        time_t leftTime = 0;
        for (const GpgME::Subkey &s : (leftUserID.isNull() ? leftKey : leftUserID.parent()).subkeys()) {
            if (s.isBad()) {
                continue;
            }
            if (s.creationTime() > leftTime) {
                leftTime = s.creationTime();
            }
        }
        time_t rightTime = 0;
        for (const GpgME::Subkey &s : (rightUserID.isNull() ? rightKey : rightUserID.parent()).subkeys()) {
            if (s.isBad()) {
                continue;
            }
            if (s.creationTime() > rightTime) {
                rightTime = s.creationTime();
            }
        }
        if (rightTime != leftTime) {
            return leftTime > rightTime;
        }

        // as final resort we compare the fingerprints
        return strcmp((leftUserID.isNull() ? leftKey : leftUserID.parent()).primaryFingerprint(),
                      (rightUserID.isNull() ? rightKey : rightUserID.parent()).primaryFingerprint())
            < 0;
    }
};

auto createSeparatorAction(QObject *parent)
{
    auto action = new QAction{parent};
    action->setSeparator(true);
    return action;
}
} // namespace

class CertificateLineEdit::Private
{
    CertificateLineEdit *q;

public:
    enum class Status {
        Empty, //< text is empty
        Success, //< a certificate or group is set
        None, //< entered text does not match any certificates or groups
        Ambiguous, //< entered text matches multiple certificates or groups
        Revoked, //< the selected cert is revoked
        Expired, //< the selected cert is expired
    };
    enum class CursorPositioning {
        MoveToEnd,
        KeepPosition,
        MoveToStart,
        Default = MoveToEnd,
    };

    explicit Private(CertificateLineEdit *qq, AbstractKeyListModel *model, KeyUsage::Flags usage, KeyFilter *filter);

    QString text() const;

    void setKey(const GpgME::Key &key);

    void setGroup(const KeyGroup &group);

    void setUserID(const GpgME::UserID &userID);

    void setKeyFilter(const std::shared_ptr<KeyFilter> &filter);

    void setAccessibleName(const QString &s);

private:
    void updateKey(CursorPositioning positioning);
    void editChanged();
    void editFinished();
    void checkLocate();
    void onLocateJobResult(QGpgME::Job *job, const QString &email, const KeyListResult &result, const std::vector<GpgME::Key> &keys);
    void openDetailsDialog();
    void setTextWithBlockedSignals(const QString &s, CursorPositioning positioning);
    void showContextMenu(const QPoint &pos);
    QString errorMessage() const;
    QIcon statusIcon() const;
    QString statusToolTip() const;
    void updateStatusAction();
    void updateErrorLabel();
    void updateAccessibleNameAndDescription();

public:
    Status mStatus = Status::Empty;
    bool mEditingInProgress = false;
    GpgME::Key mKey;
    KeyGroup mGroup;
    GpgME::UserID mUserId;

    struct Ui {
        explicit Ui(QWidget *parent)
            : lineEdit{parent}
            , button{parent}
            , errorLabel{parent}
        {
        }

        QLineEdit lineEdit;
        QToolButton button;
        ErrorLabel errorLabel;
    } ui;

private:
    QString mAccessibleName;
    UserIDProxyModel *const mUserIdProxyModel;
    KeyListSortFilterProxyModel *const mFilterModel;
    CompletionProxyModel *const mCompleterFilterModel;
    QCompleter *mCompleter = nullptr;
    std::shared_ptr<KeyFilter> mFilter;
    QAction *const mStatusAction;
    QAction *const mShowDetailsAction;
    QPointer<QGpgME::Job> mLocateJob;
    Formatting::IconProvider mIconProvider;
};

CertificateLineEdit::Private::Private(CertificateLineEdit *qq, AbstractKeyListModel *model, KeyUsage::Flags usage, KeyFilter *filter)
    : q{qq}
    , ui{qq}
    , mUserIdProxyModel{new UserIDProxyModel{qq}}
    , mFilterModel{new KeyListSortFilterProxyModel{qq}}
    , mCompleterFilterModel{new CompletionProxyModel{qq}}
    , mCompleter{new QCompleter{qq}}
    , mFilter{std::shared_ptr<KeyFilter>{filter}}
    , mStatusAction{new QAction{qq}}
    , mShowDetailsAction{new QAction{qq}}
    , mIconProvider{usage}
{
    ui.lineEdit.setPlaceholderText(i18n("Please enter a name or email address..."));
    ui.lineEdit.setClearButtonEnabled(true);
    ui.lineEdit.setContextMenuPolicy(Qt::CustomContextMenu);
    ui.lineEdit.addAction(mStatusAction, QLineEdit::LeadingPosition);

    mUserIdProxyModel->setSourceModel(model);

    mCompleterFilterModel->setKeyFilter(mFilter);
    mCompleterFilterModel->setSourceModel(mUserIdProxyModel);
    // initialize dynamic sorting
    mCompleterFilterModel->sort(0);
    mCompleter->setModel(mCompleterFilterModel);
    mCompleter->setFilterMode(Qt::MatchContains);
    mCompleter->setCaseSensitivity(Qt::CaseInsensitive);
    ui.lineEdit.setCompleter(mCompleter);

    ui.button.setIcon(QIcon::fromTheme(QStringLiteral("resource-group-new")));
    ui.button.setToolTip(i18n("Show certificate list"));
    ui.button.setAccessibleName(i18n("Show certificate list"));

    ui.errorLabel.setVisible(false);

    auto vbox = new QVBoxLayout{q};
    vbox->setContentsMargins(0, 0, 0, 0);

    auto l = new QHBoxLayout;
    l->setContentsMargins(0, 0, 0, 0);
    l->addWidget(&ui.lineEdit);
    l->addWidget(&ui.button);

    vbox->addLayout(l);
    vbox->addWidget(&ui.errorLabel);

    q->setFocusPolicy(ui.lineEdit.focusPolicy());
    q->setFocusProxy(&ui.lineEdit);

    mShowDetailsAction->setIcon(QIcon::fromTheme(QStringLiteral("help-about")));
    mShowDetailsAction->setText(i18nc("@action:inmenu", "Show Details"));
    mShowDetailsAction->setEnabled(false);

    mFilterModel->setSourceModel(mUserIdProxyModel);
    mFilterModel->setFilterKeyColumn(KeyList::Summary);
    if (filter) {
        mFilterModel->setKeyFilter(mFilter);
    }

    connect(KeyCache::instance().get(), &Kleo::KeyCache::keysMayHaveChanged, q, [this]() {
        updateKey(CursorPositioning::KeepPosition);
    });
    connect(KeyCache::instance().get(), &Kleo::KeyCache::groupUpdated, q, [this](const KeyGroup &group) {
        if (!mGroup.isNull() && mGroup.source() == group.source() && mGroup.id() == group.id()) {
            setTextWithBlockedSignals(Formatting::summaryLine(group), CursorPositioning::KeepPosition);
            // queue the update to ensure that the model has been updated
            QMetaObject::invokeMethod(
                q,
                [this]() {
                    updateKey(CursorPositioning::KeepPosition);
                },
                Qt::QueuedConnection);
        }
    });
    connect(KeyCache::instance().get(), &Kleo::KeyCache::groupRemoved, q, [this](const KeyGroup &group) {
        if (!mGroup.isNull() && mGroup.source() == group.source() && mGroup.id() == group.id()) {
            mGroup = KeyGroup();
            QSignalBlocker blocky{&ui.lineEdit};
            ui.lineEdit.clear();
            // queue the update to ensure that the model has been updated
            QMetaObject::invokeMethod(
                q,
                [this]() {
                    updateKey(CursorPositioning::KeepPosition);
                },
                Qt::QueuedConnection);
        }
    });
    connect(&ui.lineEdit, &QLineEdit::editingFinished, q, [this]() {
        // queue the call of editFinished() to ensure that QCompleter::activated is handled first
        QMetaObject::invokeMethod(
            q,
            [this]() {
                editFinished();
            },
            Qt::QueuedConnection);
    });
    connect(&ui.lineEdit, &QLineEdit::textChanged, q, [this]() {
        editChanged();
    });
    connect(&ui.lineEdit, &QLineEdit::customContextMenuRequested, q, [this](const QPoint &pos) {
        showContextMenu(pos);
    });
    connect(mStatusAction, &QAction::triggered, q, [this]() {
        openDetailsDialog();
    });
    connect(mShowDetailsAction, &QAction::triggered, q, [this]() {
        openDetailsDialog();
    });
    connect(&ui.button, &QToolButton::clicked, q, &CertificateLineEdit::certificateSelectionRequested);
    connect(mCompleter, qOverload<const QModelIndex &>(&QCompleter::activated), q, [this](const QModelIndex &index) {
        Key key = mCompleter->completionModel()->data(index, KeyList::KeyRole).value<Key>();
        auto group = mCompleter->completionModel()->data(index, KeyList::GroupRole).value<KeyGroup>();
        auto userID = mCompleter->completionModel()->data(index, KeyList::UserIDRole).value<UserID>();
        if (!userID.isNull()) {
            q->setUserID(userID);
        } else if (!key.isNull()) {
            q->setKey(key);
        } else if (!group.isNull()) {
            q->setGroup(group);
        } else {
            qCDebug(KLEOPATRA_LOG) << "Activated item is neither key, nor userid, or group";
        }
        // queue the call of editFinished() to ensure that QLineEdit finished its own work
        QMetaObject::invokeMethod(
            q,
            [this]() {
                editFinished();
            },
            Qt::QueuedConnection);
    });
    updateKey(CursorPositioning::Default);
}

void CertificateLineEdit::Private::openDetailsDialog()
{
    if (!q->key().isNull()) {
        auto cmd = new Commands::DetailsCommand{q->key()};
        cmd->setParentWidget(q);
        cmd->start();
    } else if (!q->group().isNull()) {
        auto dlg = new Dialogs::GroupDetailsDialog{q};
        dlg->setAttribute(Qt::WA_DeleteOnClose);
        dlg->setGroup(q->group());
        dlg->show();
    }
}

void CertificateLineEdit::Private::setTextWithBlockedSignals(const QString &s, CursorPositioning positioning)
{
    QSignalBlocker blocky{&ui.lineEdit};
    const auto cursorPos = ui.lineEdit.cursorPosition();
    ui.lineEdit.setText(s);
    switch (positioning) {
    case CursorPositioning::KeepPosition:
        ui.lineEdit.setCursorPosition(cursorPos);
        break;
    case CursorPositioning::MoveToStart:
        ui.lineEdit.setCursorPosition(0);
        break;
    case CursorPositioning::MoveToEnd:
    default:; // setText() already moved the cursor to the end of the line
    };
}

void CertificateLineEdit::Private::showContextMenu(const QPoint &pos)
{
    if (QMenu *menu = ui.lineEdit.createStandardContextMenu()) {
        auto *const firstStandardAction = menu->actions().value(0);
        menu->insertActions(firstStandardAction, {mShowDetailsAction, createSeparatorAction(menu)});
        menu->setAttribute(Qt::WA_DeleteOnClose);
        menu->popup(ui.lineEdit.mapToGlobal(pos));
    }
}

CertificateLineEdit::CertificateLineEdit(AbstractKeyListModel *model, KeyUsage::Flags usage, KeyFilter *filter, QWidget *parent)
    : QWidget{parent}
    , d{new Private{this, model, usage, filter}}
{
    /* Take ownership of the model to prevent double deletion when the
     * filter models are deleted */
    model->setParent(parent ? parent : this);
}

CertificateLineEdit::~CertificateLineEdit() = default;

void CertificateLineEdit::Private::editChanged()
{
    const bool editingStarted = !mEditingInProgress;
    mEditingInProgress = true;
    updateKey(CursorPositioning::Default);
    if (editingStarted) {
        Q_EMIT q->editingStarted();
    }
    if (q->isEmpty()) {
        Q_EMIT q->cleared();
    }
}

void CertificateLineEdit::Private::editFinished()
{
    // perform a first update with the "editing in progress" flag still set
    updateKey(CursorPositioning::MoveToStart);
    mEditingInProgress = false;
    checkLocate();
    // perform another update with the "editing in progress" flag cleared
    // after a key locate may have been started; this makes sure that displaying
    // an error is delayed until the key locate job has finished
    updateKey(CursorPositioning::MoveToStart);
}

void CertificateLineEdit::Private::checkLocate()
{
    if (mStatus != Status::None) {
        // try to locate key only if text matches no local certificates, user ids, or groups
        return;
    }

    // Only check once per mailbox
    const auto mailText = ui.lineEdit.text().trimmed();
    if (mailText.isEmpty() || s_lookedUpKeys.contains(mailText)) {
        return;
    }
    s_lookedUpKeys << mailText;
    if (mLocateJob) {
        mLocateJob->slotCancel();
        mLocateJob.clear();
    }
    auto job = QGpgME::openpgp()->locateKeysJob();
    connect(job, &QGpgME::KeyListJob::result, q, [this, job, mailText](const KeyListResult &result, const std::vector<GpgME::Key> &keys) {
        onLocateJobResult(job, mailText, result, keys);
    });
    if (auto err = job->start({mailText}, /*secretOnly=*/false)) {
        qCDebug(KLEOPATRA_LOG) << __func__ << "Error: Starting" << job << "for" << mailText << "failed with" << Formatting::errorAsString(err);
    } else {
        mLocateJob = job;
        qCDebug(KLEOPATRA_LOG) << __func__ << "Started" << job << "for" << mailText;
    }
}

void CertificateLineEdit::Private::onLocateJobResult(QGpgME::Job *job, const QString &email, const KeyListResult &result, const std::vector<GpgME::Key> &keys)
{
    if (mLocateJob != job) {
        qCDebug(KLEOPATRA_LOG) << __func__ << "Ignoring outdated finished" << job << "for" << email;
        return;
    }
    qCDebug(KLEOPATRA_LOG) << __func__ << job << "for" << email << "finished with" << Formatting::errorAsString(result.error()) << "and keys" << keys;
    mLocateJob.clear();
    if (!keys.empty() && !keys.front().isNull()) {
        KeyCache::mutableInstance()->insert(keys.front());
        // inserting the key implicitly triggers an update
    } else {
        // explicitly trigger an update to display "no key" error
        updateKey(CursorPositioning::MoveToStart);
    }
}

void CertificateLineEdit::Private::updateKey(CursorPositioning positioning)
{
    static const _detail::ByFingerprint<std::equal_to> keysHaveSameFingerprint;

    const auto mailText = ui.lineEdit.text().trimmed();
    auto newKey = Key();
    auto newGroup = KeyGroup();
    auto newUserId = UserID();
    if (mailText.isEmpty()) {
        mStatus = Status::Empty;
    } else {
        mFilterModel->setFilterRegularExpression(QRegularExpression::escape(mailText));
        if (mFilterModel->rowCount() > 1) {
            // keep current key, user id, or group if they still match
            if (!mKey.isNull()) {
                for (int row = 0; row < mFilterModel->rowCount(); ++row) {
                    const QModelIndex index = mFilterModel->index(row, 0);
                    Key key = mFilterModel->key(index);
                    if (!key.isNull() && keysHaveSameFingerprint(key, mKey)) {
                        newKey = mKey;
                        break;
                    }
                }
            } else if (!mGroup.isNull()) {
                newGroup = mGroup;
                for (int row = 0; row < mFilterModel->rowCount(); ++row) {
                    const QModelIndex index = mFilterModel->index(row, 0);
                    KeyGroup group = mFilterModel->group(index);
                    if (!group.isNull() && group.source() == mGroup.source() && group.id() == mGroup.id()) {
                        newGroup = mGroup;
                        break;
                    }
                }
            } else if (!mUserId.isNull()) {
                for (int row = 0; row < mFilterModel->rowCount(); ++row) {
                    const QModelIndex index = mFilterModel->index(row, 0);
                    UserID userId = index.data(KeyList::UserIDRole).value<UserID>();
                    if (!userId.isNull() && keysHaveSameFingerprint(userId.parent(), mUserId.parent()) && !strcmp(userId.id(), mUserId.id())) {
                        newUserId = mUserId;
                    }
                }
            }
            if (newKey.isNull() && newGroup.isNull() && newUserId.isNull()) {
                mStatus = Status::Ambiguous;
            }
        } else if (mFilterModel->rowCount() == 1) {
            const auto index = mFilterModel->index(0, 0);
            newUserId = mFilterModel->data(index, KeyList::UserIDRole).value<UserID>();
            if (newUserId.isNull()) {
                newKey = mFilterModel->data(index, KeyList::KeyRole).value<Key>();
            }
            newGroup = mFilterModel->data(index, KeyList::GroupRole).value<KeyGroup>();
            Q_ASSERT(!newKey.isNull() || !newGroup.isNull() || !newUserId.isNull());
            if (newKey.isNull() && newGroup.isNull() && newUserId.isNull()) {
                mStatus = Status::None;
            }
        } else {
            if (!mUserId.isNull() && (mUserId.isRevoked() || mUserId.parent().isRevoked())) {
                mStatus = Status::Revoked;
            } else if (!mUserId.isNull() && mUserId.parent().isExpired()) {
                mStatus = Status::Expired;
            } else {
                mStatus = Status::None;
            }
        }
    }
    mKey = newKey;
    mGroup = newGroup;
    mUserId = newUserId;

    if (!mKey.isNull()) {
        /* FIXME: This needs to be solved by a multiple UID supporting model */
        mStatus = Status::Success;
        ui.lineEdit.setToolTip(Formatting::toolTip(mKey, Formatting::ToolTipOption::AllOptions));
        if (!mEditingInProgress) {
            setTextWithBlockedSignals(Formatting::summaryLine(mKey), positioning);
        }
    } else if (!mGroup.isNull()) {
        mStatus = Status::Success;
        ui.lineEdit.setToolTip(Formatting::toolTip(mGroup, Formatting::ToolTipOption::AllOptions));
        if (!mEditingInProgress) {
            setTextWithBlockedSignals(Formatting::summaryLine(mGroup), positioning);
        }
    } else if (!mUserId.isNull()) {
        mStatus = Status::Success;
        ui.lineEdit.setToolTip(Formatting::toolTip(mUserId, Formatting::ToolTipOption::AllOptions));
        if (!mEditingInProgress) {
            setTextWithBlockedSignals(Formatting::summaryLine(mUserId), positioning);
        }
    } else {
        ui.lineEdit.setToolTip({});
    }

    mShowDetailsAction->setEnabled(mStatus == Status::Success);
    updateStatusAction();
    updateErrorLabel();

    Q_EMIT q->keyChanged();
}

QString CertificateLineEdit::Private::errorMessage() const
{
    switch (mStatus) {
    case Status::Empty:
    case Status::Success:
        return {};
    case Status::None:
        return i18n("No matching certificates or groups found");
    case Status::Ambiguous:
        return i18n("Multiple matching certificates or groups found");
    case Status::Expired:
        return i18n("This certificate is expired");
    case Status::Revoked:
        return i18n("This certificate is revoked");
    default:
        qDebug(KLEOPATRA_LOG) << __func__ << "Invalid status:" << static_cast<int>(mStatus);
        Q_ASSERT(!"Invalid status");
    };
    return {};
}

QIcon CertificateLineEdit::Private::statusIcon() const
{
    switch (mStatus) {
    case Status::Empty:
        return QIcon::fromTheme(QStringLiteral("emblem-unavailable"));
    case Status::Success:
        if (!mKey.isNull()) {
            return mIconProvider.icon(mKey);
        } else if (!mGroup.isNull()) {
            return mIconProvider.icon(mGroup);
        } else if (!mUserId.isNull()) {
            return mIconProvider.icon(mUserId);
        } else {
            qDebug(KLEOPATRA_LOG) << __func__ << "Success, but neither key, nor user id, or group.";
            return {};
        }
    case Status::None:
    case Status::Ambiguous:
        if (mEditingInProgress || mLocateJob) {
            return QIcon::fromTheme(QStringLiteral("emblem-question"));
        } else {
            return QIcon::fromTheme(QStringLiteral("emblem-error"));
        }
    case Status::Expired:
    case Status::Revoked:
        return QIcon::fromTheme(QStringLiteral("emblem-error"));
    default:
        qDebug(KLEOPATRA_LOG) << __func__ << "Invalid status:" << static_cast<int>(mStatus);
        Q_ASSERT(!"Invalid status");
    };
    return {};
}

QString CertificateLineEdit::Private::statusToolTip() const
{
    switch (mStatus) {
    case Status::Empty:
        return {};
    case Status::Success:
        if (!mUserId.isNull()) {
            return Formatting::validity(mUserId);
        }
        if (!mKey.isNull()) {
            return Formatting::validity(mKey.userID(0));
        } else if (!mGroup.isNull()) {
            return Formatting::validity(mGroup);
        } else {
            qDebug(KLEOPATRA_LOG) << __func__ << "Success, but neither key, nor user id, or group.";
            return {};
        }
    case Status::None:
    case Status::Ambiguous:
        return errorMessage();
    default:
        qDebug(KLEOPATRA_LOG) << __func__ << "Invalid status:" << static_cast<int>(mStatus);
        Q_ASSERT(!"Invalid status");
    };
    return {};
}

void CertificateLineEdit::Private::updateStatusAction()
{
    mStatusAction->setIcon(statusIcon());
    mStatusAction->setToolTip(statusToolTip());
}

namespace
{
QString decoratedError(const QString &text)
{
    return text.isEmpty() ? QString() : i18nc("@info", "Error: %1", text);
}
}

void CertificateLineEdit::Private::updateErrorLabel()
{
    const auto currentErrorMessage = ui.errorLabel.text();
    const auto newErrorMessage = decoratedError(errorMessage());
    if (newErrorMessage == currentErrorMessage) {
        return;
    }
    if (currentErrorMessage.isEmpty() && (mEditingInProgress || mLocateJob)) {
        // delay showing the error message until editing is finished, so that we
        // do not annoy the user with an error message while they are still
        // entering the recipient;
        // on the other hand, we clear the error message immediately if it does
        // not apply anymore and we update the error message immediately if it
        // changed
        return;
    }
    ui.errorLabel.setVisible(!newErrorMessage.isEmpty());
    ui.errorLabel.setText(newErrorMessage);
    updateAccessibleNameAndDescription();
}

void CertificateLineEdit::Private::setAccessibleName(const QString &s)
{
    mAccessibleName = s;
    updateAccessibleNameAndDescription();
}

void CertificateLineEdit::Private::updateAccessibleNameAndDescription()
{
    // fall back to default accessible name if accessible name wasn't set explicitly
    if (mAccessibleName.isEmpty()) {
        mAccessibleName = getAccessibleName(&ui.lineEdit);
    }
    const bool errorShown = ui.errorLabel.isVisible();

    // Qt does not support "described-by" relations (like WCAG's "aria-describedby" relationship attribute);
    // emulate this by setting the error message as accessible description of the input field
    const auto description = errorShown ? ui.errorLabel.text() : QString{};
    if (ui.lineEdit.accessibleDescription() != description) {
        ui.lineEdit.setAccessibleDescription(description);
    }

    // Qt does not support IA2's "invalid entry" state (like WCAG's "aria-invalid" state attribute);
    // screen readers say something like "invalid data" if this state is set;
    // emulate this by adding "invalid data" to the accessible name of the input field
    const auto name = errorShown ? mAccessibleName + QLatin1String{", "} + invalidEntryText() //
                                 : mAccessibleName;
    if (ui.lineEdit.accessibleName() != name) {
        ui.lineEdit.setAccessibleName(name);
    }
}

Key CertificateLineEdit::key() const
{
    if (isEnabled()) {
        return d->mKey;
    } else {
        return Key();
    }
}

KeyGroup CertificateLineEdit::group() const
{
    if (isEnabled()) {
        return d->mGroup;
    } else {
        return KeyGroup();
    }
}

UserID CertificateLineEdit::userID() const
{
    if (isEnabled()) {
        return d->mUserId;
    } else {
        return UserID();
    }
}

QString CertificateLineEdit::Private::text() const
{
    return ui.lineEdit.text().trimmed();
}

QString CertificateLineEdit::text() const
{
    return d->text();
}

void CertificateLineEdit::Private::setKey(const Key &key)
{
    mKey = key;
    mGroup = KeyGroup();
    mUserId = UserID();
    qCDebug(KLEOPATRA_LOG) << "Setting Key. " << Formatting::summaryLine(key);
    // position cursor, so that that the start of the summary is visible
    setTextWithBlockedSignals(Formatting::summaryLine(key), CursorPositioning::MoveToStart);
    updateKey(CursorPositioning::MoveToStart);
}

void CertificateLineEdit::setKey(const Key &key)
{
    d->setKey(key);
}

void CertificateLineEdit::Private::setUserID(const UserID &userID)
{
    mUserId = userID;
    mKey = Key();
    mGroup = KeyGroup();
    qCDebug(KLEOPATRA_LOG) << "Setting UserID. " << Formatting::summaryLine(userID);
    // position cursor, so that the start of the summary is visible
    setTextWithBlockedSignals(Formatting::summaryLine(userID), CursorPositioning::MoveToStart);
    updateKey(CursorPositioning::MoveToStart);
}

void CertificateLineEdit::setUserID(const UserID &userID)
{
    d->setUserID(userID);
}

void CertificateLineEdit::Private::setGroup(const KeyGroup &group)
{
    mGroup = group;
    mKey = Key();
    mUserId = UserID();
    const QString summary = Formatting::summaryLine(group);
    qCDebug(KLEOPATRA_LOG) << "Setting KeyGroup. " << summary;
    // position cursor, so that that the start of the summary is visible
    setTextWithBlockedSignals(summary, CursorPositioning::MoveToStart);
    updateKey(CursorPositioning::MoveToStart);
}

void CertificateLineEdit::setGroup(const KeyGroup &group)
{
    d->setGroup(group);
}

bool CertificateLineEdit::isEmpty() const
{
    return d->mStatus == Private::Status::Empty;
}

bool CertificateLineEdit::isEditingInProgress() const
{
    return d->mEditingInProgress;
}

bool CertificateLineEdit::hasAcceptableInput() const
{
    return d->mStatus == Private::Status::Empty //
        || d->mStatus == Private::Status::Success;
}

void CertificateLineEdit::Private::setKeyFilter(const std::shared_ptr<KeyFilter> &filter)
{
    mFilter = filter;
    mFilterModel->setKeyFilter(filter);
    mCompleterFilterModel->setKeyFilter(mFilter);
    updateKey(CursorPositioning::Default);
}

void CertificateLineEdit::setKeyFilter(const std::shared_ptr<KeyFilter> &filter)
{
    d->setKeyFilter(filter);
}

void CertificateLineEdit::setAccessibleNameOfLineEdit(const QString &name)
{
    d->setAccessibleName(name);
}

#include "certificatelineedit.moc"
