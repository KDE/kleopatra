// SPDX-FileCopyrightText: 2024 g10 Code GmbH
// SPDX-FileContributor: Tobias Fella <tobias.fella@gnupg.com>
// SPDX-License-Identifier: GPL-2.0-or-later

#include "useridswidget.h"

#include "commands/adduseridcommand.h"
#include "commands/certifycertificatecommand.h"
#include "commands/revokecertificationcommand.h"
#include "commands/revokeuseridcommand.h"
#include "commands/setprimaryuseridcommand.h"
#ifdef MAILAKONADI_ENABLED
#include "commands/exportopenpgpcerttoprovidercommand.h"
#endif // MAILAKONADI_ENABLED

#include "utils/tags.h"

#include <Libkleo/Formatting>
#include <Libkleo/KeyCache>
#include <Libkleo/KeyHelpers>
#include <Libkleo/TreeView>
#include <Libkleo/TreeWidget>
#include <Libkleo/UserIDListModel>

#include <KLocalizedString>
#include <KMessageBox>
#include <KSeparator>

#include <QDateTime>
#include <QDialogButtonBox>
#include <QHeaderView>
#include <QMenu>
#include <QPushButton>
#include <QVBoxLayout>

#include <QGpgME/KeyListJob>
#include <QGpgME/Protocol>

#include <gpgme++/key.h>
#include <gpgme++/keylistresult.h>
#include <gpgme++/tofuinfo.h>

#include "kleopatra_debug.h"

using namespace Kleo;

namespace
{
std::vector<GpgME::UserID> selectedUserIDs(const QTreeWidget *treeWidget)
{
    if (!treeWidget) {
        return {};
    }

    std::vector<GpgME::UserID> userIDs;
    const auto selected = treeWidget->selectedItems();
    std::transform(selected.begin(), selected.end(), std::back_inserter(userIDs), [](const QTreeWidgetItem *item) {
        return item->data(0, Qt::UserRole).value<GpgME::UserID>();
    });
    return userIDs;
}

static QPushButton *addActionButton(QLayout *buttonBox, QAction *action)
{
    if (!action) {
        return nullptr;
    }
    auto button = new QPushButton(buttonBox->parentWidget());
    button->setText(action->text());
    buttonBox->addWidget(button);
    button->setEnabled(action->isEnabled());
    QObject::connect(action, &QAction::changed, button, [action, button]() {
        button->setEnabled(action->isEnabled());
    });
    QObject::connect(button, &QPushButton::clicked, action, &QAction::trigger);
    return button;
}
}

class UserIdsWidget::Private
{
public:
    enum Columns {
        Name,
        Email,
        TrustLevel,
        Origin,
        Tags,
    };

    Private(UserIdsWidget *qq)
        : q{qq}
    {
    }

    TreeWidget *userIDTable = nullptr;
    QPushButton *addUserIDBtn = nullptr;
    QPushButton *revokeUserIDBtn = nullptr;
    QPushButton *certifyBtn = nullptr;
    QPushButton *revokeCertificationsBtn = nullptr;
    QAction *setPrimaryUserIDAction = nullptr;
    QAction *certifyAction = nullptr;
    QAction *revokeCertificationsAction = nullptr;
    GpgME::Key key;
    bool updateInProgress = false;
    QPushButton *moreButton = nullptr;
    QHBoxLayout *buttonRow = nullptr;

    QString trustLevelText(const GpgME::UserID &uid) const;
    QIcon trustLevelIcon(const GpgME::UserID &uid) const;
    QString tofuTooltipString(const GpgME::UserID &uid) const;
    void setUpUserIDTable();
    void addUserID();
    void updateUserIDActions();
    void setPrimaryUserID(const GpgME::UserID &uid = {});
    void certifyUserIDs();
    void revokeCertifications();
    void revokeUserID(const GpgME::UserID &uid);
    void revokeSelectedUserID();
    void userIDTableContextMenuRequested(const QPoint &p);

private:
    UserIdsWidget *const q;
};

UserIdsWidget::UserIdsWidget(QWidget *parent)
    : QWidget{parent}
    , d{std::make_unique<Private>(this)}
{
    auto userIDsLayout = new QVBoxLayout{this};
    userIDsLayout->setContentsMargins({});

    d->userIDTable = new TreeWidget{parent};
    d->userIDTable->setAccessibleName(i18n("User IDs"));
    QTreeWidgetItem *__qtreewidgetitem = new QTreeWidgetItem();
    __qtreewidgetitem->setText(0, QString::fromUtf8("1"));
    d->userIDTable->setHeaderItem(__qtreewidgetitem);
    d->userIDTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    d->userIDTable->setSelectionMode(QAbstractItemView::ExtendedSelection);
    d->userIDTable->setRootIsDecorated(false);
    d->userIDTable->setUniformRowHeights(true);
    d->userIDTable->setAllColumnsShowFocus(false);

    userIDsLayout->addWidget(d->userIDTable);

    d->buttonRow = new QHBoxLayout;

    d->addUserIDBtn = new QPushButton(i18nc("@action:button", "Add User ID"), parent);
    d->buttonRow->addWidget(d->addUserIDBtn);

    d->revokeUserIDBtn = new QPushButton(i18nc("@action:button", "Revoke User ID"), parent);
    d->buttonRow->addWidget(d->revokeUserIDBtn);

    d->setPrimaryUserIDAction = new QAction({}, i18nc("@action:button", "Flag as Primary"));
    d->setPrimaryUserIDAction->setToolTip(i18nc("@info:tooltip", "Flag the selected user ID as the primary user ID of this key."));

    d->certifyAction = new QAction({}, i18nc("@action:button", "Certify User IDs"));
    d->revokeCertificationsAction = new QAction({}, i18nc("@action:button", "Revoke Certifications"));

    d->certifyBtn = addActionButton(d->buttonRow, d->certifyAction);
    d->revokeCertificationsBtn = addActionButton(d->buttonRow, d->revokeCertificationsAction);

    d->moreButton = new QPushButton(QIcon::fromTheme(QStringLiteral("application-menu")), {});
    d->moreButton->setToolTip(i18nc("@info:tooltip", "Show more options"));
    d->buttonRow->addWidget(d->moreButton);
    connect(d->moreButton, &QPushButton::clicked, this, [this]() {
        auto menu = new QMenu(this);
        menu->addAction(d->setPrimaryUserIDAction);
        menu->addAction(d->certifyAction);
        menu->addAction(d->revokeCertificationsAction);
        menu->popup(d->moreButton->mapToGlobal(QPoint()));
    });

    d->buttonRow->addStretch(1);

    userIDsLayout->addLayout(d->buttonRow);
    setLayout(userIDsLayout);

    connect(d->addUserIDBtn, &QPushButton::clicked, this, [this]() {
        d->addUserID();
    });
    connect(d->userIDTable, &QTreeWidget::itemSelectionChanged, this, [this]() {
        d->updateUserIDActions();
    });
    connect(d->setPrimaryUserIDAction, &QAction::triggered, this, [this]() {
        d->setPrimaryUserID();
    });
    connect(d->certifyAction, &QAction::triggered, this, [this]() {
        d->certifyUserIDs();
    });
    connect(d->revokeCertificationsAction, &QAction::triggered, this, [this]() {
        d->revokeCertifications();
    });
    connect(d->revokeUserIDBtn, &QPushButton::clicked, this, [this]() {
        d->revokeSelectedUserID();
    });

    d->userIDTable->setContextMenuPolicy(Qt::CustomContextMenu);
    connect(d->userIDTable, &QAbstractItemView::customContextMenuRequested, this, [this](const QPoint &p) {
        d->userIDTableContextMenuRequested(p);
    });
}

void UserIdsWidget::Private::updateUserIDActions()
{
    const auto userIDs = selectedUserIDs(userIDTable);
    const auto singleUserID = userIDs.size() == 1 ? userIDs.front() : GpgME::UserID{};
    const bool isPrimaryUserID = !singleUserID.isNull() && (userIDTable->selectedItems().front() == userIDTable->topLevelItem(0));
    setPrimaryUserIDAction->setEnabled(!singleUserID.isNull() //
                                       && !isPrimaryUserID //
                                       && !Kleo::isRevokedOrExpired(singleUserID) //
                                       && canBeUsedForSecretKeyOperations(key));
    revokeUserIDBtn->setEnabled(!singleUserID.isNull() && canCreateCertifications(key) && canRevokeUserID(singleUserID));
}

UserIdsWidget::~UserIdsWidget() = default;

GpgME::Key UserIdsWidget::key() const
{
    return d->key;
}

void UserIdsWidget::setKey(const GpgME::Key &key)
{
    d->key = key;
    d->setUpUserIDTable();
    const bool isOwnKey = key.hasSecret();
    const auto isLocalKey = !isRemoteKey(key);
    const auto keyCanBeCertified = Kleo::canBeCertified(key);
    const auto userCanSignUserIDs = userHasCertificationKey();

    d->addUserIDBtn->setVisible(isOwnKey);
    d->addUserIDBtn->setEnabled(canBeUsedForSecretKeyOperations(key));
    d->setPrimaryUserIDAction->setVisible(isOwnKey);
    d->setPrimaryUserIDAction->setEnabled(false); // requires a selected user ID
    d->certifyAction->setVisible(true); // always visible (for OpenPGP keys)
    d->certifyBtn->setVisible(!isOwnKey);
    d->revokeCertificationsBtn->setVisible(!isOwnKey);
    d->moreButton->setVisible(isOwnKey);
    d->certifyAction->setEnabled(isLocalKey && keyCanBeCertified && userCanSignUserIDs);
    d->revokeCertificationsAction->setVisible(Kleo::Commands::RevokeCertificationCommand::isSupported());
    d->revokeCertificationsAction->setEnabled(userCanSignUserIDs && isLocalKey);
    d->revokeUserIDBtn->setVisible(isOwnKey);
    d->revokeUserIDBtn->setEnabled(false); // requires a selected user ID
}

void UserIdsWidget::Private::setUpUserIDTable()
{
    userIDTable->clear();

    QStringList headers = {
        i18n("Name"),
        i18n("Email"),
        i18n("Trust Level"),
        i18n("Origin"),
        i18n("Tags"),
    };
    userIDTable->setColumnCount(headers.count());
    userIDTable->setColumnWidth(Name, 200);
    userIDTable->setColumnWidth(Email, 200);
    userIDTable->setHeaderLabels(headers);

    const auto uids = key.userIDs();
    for (unsigned int i = 0; i < uids.size(); ++i) {
        const auto &uid = uids[i];
        auto item = new QTreeWidgetItem;
        const QString toolTip = tofuTooltipString(uid);
        item->setData(Name, Qt::UserRole, QVariant::fromValue(uid));

        auto pMail = Kleo::Formatting::prettyEMail(uid);
        auto pName = Kleo::Formatting::prettyName(uid);

        item->setData(Name, Qt::DisplayRole, pName);
        item->setData(Name, Qt::ToolTipRole, toolTip);
        item->setData(Email, Qt::DisplayRole, pMail);
        item->setData(Email, Qt::ToolTipRole, toolTip);
        item->setData(Email, Qt::AccessibleTextRole, pMail.isEmpty() ? i18nc("text for screen readers for an empty email address", "no email") : pMail);

        item->setData(TrustLevel, Qt::DecorationRole, trustLevelIcon(uid));
        item->setData(TrustLevel, Qt::DisplayRole, trustLevelText(uid));
        item->setData(TrustLevel, Qt::ToolTipRole, toolTip);

        item->setData(Origin, Qt::DisplayRole, Formatting::origin(uid.origin()));
        GpgME::Error err;
        QStringList tagList;
        for (const auto &tag : uid.remarks(Tags::tagKeys(), err)) {
            if (err) {
                qCWarning(KLEOPATRA_LOG) << "Getting remarks for user ID" << uid.id() << "failed:" << err;
            }
            tagList << QString::fromStdString(tag);
        }
        qCDebug(KLEOPATRA_LOG) << "tagList:" << tagList;
        const auto tags = tagList.join(QStringLiteral("; "));
        item->setData(Tags, Qt::DisplayRole, tags);
        item->setData(Tags, Qt::ToolTipRole, toolTip);

        userIDTable->addTopLevelItem(item);
    }
    if (!userIDTable->restoreColumnLayout(QStringLiteral("UserIDTable"))) {
        userIDTable->hideColumn(Tags);
    }
    userIDTable->resizeToContentsLimited();
}

QString UserIdsWidget::Private::tofuTooltipString(const GpgME::UserID &uid) const
{
    const auto tofu = uid.tofuInfo();
    if (tofu.isNull()) {
        return QString();
    }

    QString html = QStringLiteral("<table border=\"0\" cell-padding=\"5\">");
    const auto appendRow = [&html](const QString &lbl, const QString &val) {
        html += QStringLiteral(
                    "<tr>"
                    "<th style=\"text-align: right; padding-right: 5px; white-space: nowrap;\">%1:</th>"
                    "<td style=\"white-space: nowrap;\">%2</td>"
                    "</tr>")
                    .arg(lbl, val);
    };
    const auto appendHeader = [this, &html](const QString &hdr) {
        html += QStringLiteral("<tr><th colspan=\"2\" style=\"background-color: %1; color: %2\">%3</th></tr>")
                    .arg(q->palette().highlight().color().name(), q->palette().highlightedText().color().name(), hdr);
    };
    const auto dateTime = [](long ts) {
        QLocale l;
        return ts == 0 ? i18n("never") : l.toString(QDateTime::fromSecsSinceEpoch(ts), QLocale::ShortFormat);
    };
    appendHeader(i18n("Signing"));
    appendRow(i18n("First message"), dateTime(tofu.signFirst()));
    appendRow(i18n("Last message"), dateTime(tofu.signLast()));
    appendRow(i18n("Message count"), QString::number(tofu.signCount()));
    appendHeader(i18n("Encryption"));
    appendRow(i18n("First message"), dateTime(tofu.encrFirst()));
    appendRow(i18n("Last message"), dateTime(tofu.encrLast()));
    appendRow(i18n("Message count"), QString::number(tofu.encrCount()));

    html += QStringLiteral("</table>");
    // Make sure the tooltip string is different for each UserID, even if the
    // data are the same, otherwise the tooltip is not updated and moved when
    // user moves mouse from one row to another.
    html += QStringLiteral("<!-- %1 //-->").arg(QString::fromUtf8(uid.id()));
    return html;
}

QIcon UserIdsWidget::Private::trustLevelIcon(const GpgME::UserID &uid) const
{
    if (updateInProgress) {
        return QIcon::fromTheme(QStringLiteral("emblem-question"));
    }
    switch (uid.validity()) {
    case GpgME::UserID::Unknown:
    case GpgME::UserID::Undefined:
        return QIcon::fromTheme(QStringLiteral("emblem-question"));
    case GpgME::UserID::Never:
        return QIcon::fromTheme(QStringLiteral("emblem-error"));
    case GpgME::UserID::Marginal:
        return QIcon::fromTheme(QStringLiteral("emblem-warning"));
    case GpgME::UserID::Full:
    case GpgME::UserID::Ultimate:
        return QIcon::fromTheme(QStringLiteral("emblem-success"));
    }
    return {};
}

QString UserIdsWidget::Private::trustLevelText(const GpgME::UserID &uid) const
{
    return updateInProgress ? i18n("Updating...") : Formatting::validityShort(uid);
}

void UserIdsWidget::Private::addUserID()
{
    auto cmd = new Kleo::Commands::AddUserIDCommand(key);
    QObject::connect(cmd, &Kleo::Commands::AddUserIDCommand::finished, q, [this]() {
        addUserIDBtn->setEnabled(true);
        Q_EMIT q->updateKey();
    });
    addUserIDBtn->setEnabled(false);
    cmd->start();
}

void UserIdsWidget::Private::setPrimaryUserID(const GpgME::UserID &uid)
{
    auto userId = uid;
    if (userId.isNull()) {
        const auto userIDs = selectedUserIDs(userIDTable);
        if (userIDs.size() != 1) {
            return;
        }
        userId = userIDs.front();
    }

    auto cmd = new Kleo::Commands::SetPrimaryUserIDCommand(userId);
    connect(cmd, &Kleo::Commands::SetPrimaryUserIDCommand::finished, q, [this]() {
        userIDTable->setEnabled(true);
        // the Flag As Primary button will be updated by the key update
        Q_EMIT q->updateKey();
    });
    userIDTable->setEnabled(false);
    setPrimaryUserIDAction->setEnabled(false);
    cmd->start();
}

void UserIdsWidget::Private::certifyUserIDs()
{
    const auto userIDs = selectedUserIDs(userIDTable);
    auto cmd = userIDs.empty() ? new Kleo::Commands::CertifyCertificateCommand{key} //
                               : new Kleo::Commands::CertifyCertificateCommand{userIDs};
    connect(cmd, &Kleo::Commands::CertifyCertificateCommand::finished, q, [this]() {
        Q_EMIT q->updateKey();
        certifyAction->setEnabled(true);
    });
    certifyAction->setEnabled(false);
    cmd->start();
}

void UserIdsWidget::Private::revokeCertifications()
{
    const auto userIDs = selectedUserIDs(userIDTable);
    auto cmd = userIDs.empty() ? new Kleo::Commands::RevokeCertificationCommand{key} //
                               : new Kleo::Commands::RevokeCertificationCommand{userIDs};
    connect(cmd, &Kleo::Command::finished, q, [this]() {
        Q_EMIT q->updateKey();
        revokeCertificationsAction->setEnabled(true);
    });
    revokeCertificationsAction->setEnabled(false);
    cmd->start();
}

void UserIdsWidget::Private::revokeUserID(const GpgME::UserID &userId)
{
    const QString message =
        xi18nc("@info", "<para>Do you really want to revoke the user ID<nl/><emphasis>%1</emphasis> ?</para>", QString::fromUtf8(userId.id()));
    auto confirmButton = KStandardGuiItem::ok();
    confirmButton.setText(i18nc("@action:button", "Revoke User ID"));
    confirmButton.setToolTip({});
    const auto choice = KMessageBox::questionTwoActions(q->window(),
                                                        message,
                                                        i18nc("@title:window", "Confirm Revocation"),
                                                        confirmButton,
                                                        KStandardGuiItem::cancel(),
                                                        {},
                                                        KMessageBox::Notify | KMessageBox::WindowModal);
    if (choice != KMessageBox::ButtonCode::PrimaryAction) {
        return;
    }

    auto cmd = new Commands::RevokeUserIDCommand(userId);
    cmd->setParentWidget(q);
    connect(cmd, &Command::finished, q, [this]() {
        userIDTable->setEnabled(true);
        // the Revoke User ID button will be updated by the key update
        Q_EMIT q->updateKey();
    });
    userIDTable->setEnabled(false);
    revokeUserIDBtn->setEnabled(false);
    cmd->start();
}

void UserIdsWidget::Private::revokeSelectedUserID()
{
    const auto userIDs = selectedUserIDs(userIDTable);
    if (userIDs.size() != 1) {
        return;
    }
    revokeUserID(userIDs.front());
}

void UserIdsWidget::Private::userIDTableContextMenuRequested(const QPoint &p)
{
    const auto userIDs = selectedUserIDs(userIDTable);
    const auto singleUserID = (userIDs.size() == 1) ? userIDs.front() : GpgME::UserID{};
    const bool isPrimaryUserID = !singleUserID.isNull() && (userIDTable->selectedItems().front() == userIDTable->topLevelItem(0));
    const bool canSignUserIDs = userHasCertificationKey();
    const auto isLocalKey = !isRemoteKey(key);
    const auto keyCanBeCertified = Kleo::canBeCertified(key);

    auto menu = new QMenu(q);
    if (key.hasSecret()) {
        auto action =
            menu->addAction(QIcon::fromTheme(QStringLiteral("favorite")), i18nc("@action:inmenu", "Flag as Primary User ID"), q, [this, singleUserID]() {
                setPrimaryUserID(singleUserID);
            });
        action->setEnabled(!singleUserID.isNull() //
                           && !isPrimaryUserID //
                           && !Kleo::isRevokedOrExpired(singleUserID) //
                           && canBeUsedForSecretKeyOperations(key));
    }
    {
        const auto actionText = userIDs.empty() ? i18nc("@action:inmenu", "Certify User IDs...")
                                                : i18ncp("@action:inmenu", "Certify User ID...", "Certify User IDs...", userIDs.size());
        auto action = menu->addAction(QIcon::fromTheme(QStringLiteral("view-certificate-sign")), actionText, q, [this]() {
            certifyUserIDs();
        });
        action->setEnabled(isLocalKey && keyCanBeCertified && canSignUserIDs);
    }
    if (Kleo::Commands::RevokeCertificationCommand::isSupported()) {
        const auto actionText = userIDs.empty() ? i18nc("@action:inmenu", "Revoke Certifications...")
                                                : i18ncp("@action:inmenu", "Revoke Certification...", "Revoke Certifications...", userIDs.size());
        auto action = menu->addAction(QIcon::fromTheme(QStringLiteral("view-certificate-revoke")), actionText, q, [this]() {
            revokeCertifications();
        });
        action->setEnabled(isLocalKey && canSignUserIDs);
    }
#ifdef MAILAKONADI_ENABLED
    if (key.hasSecret()) {
        auto action = menu->addAction(QIcon::fromTheme(QStringLiteral("view-certificate-export")),
                                      i18nc("@action:inmenu", "Publish at Mail Provider ..."),
                                      q,
                                      [this, singleUserID]() {
                                          auto cmd = new Kleo::Commands::ExportOpenPGPCertToProviderCommand(singleUserID);
                                          userIDTable->setEnabled(false);
                                          connect(cmd, &Kleo::Commands::ExportOpenPGPCertToProviderCommand::finished, q, [this]() {
                                              userIDTable->setEnabled(true);
                                          });
                                          cmd->start();
                                      });
        action->setEnabled(!singleUserID.isNull());
    }
#endif // MAILAKONADI_ENABLED
    {
        auto action =
            menu->addAction(QIcon::fromTheme(QStringLiteral("view-certificate-revoke")), i18nc("@action:inmenu", "Revoke User ID"), q, [this, singleUserID]() {
                revokeUserID(singleUserID);
            });
        action->setEnabled(!singleUserID.isNull() && canCreateCertifications(key) && canRevokeUserID(singleUserID));
    }
    connect(menu, &QMenu::aboutToHide, menu, &QObject::deleteLater);
    menu->popup(userIDTable->viewport()->mapToGlobal(p));
}

void UserIdsWidget::setUpdateInProgress(bool updateInProgress)
{
    d->updateInProgress = updateInProgress;
}

#include "moc_useridswidget.cpp"
