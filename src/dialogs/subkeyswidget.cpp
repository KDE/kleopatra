/*
    dialogs/subkeyswidget.cpp

    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2016 Klarälvdalens Datakonsult AB
    SPDX-FileCopyrightText: 2017 Bundesamt für Sicherheit in der Informationstechnik
    SPDX-FileContributor: Intevation GmbH
    SPDX-FileCopyrightText: 2022 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include <config-kleopatra.h>

#include "subkeyswidget.h"

#include "commands/addadskcommand.h"
#include "commands/addsubkeycommand.h"
#include "commands/changeexpirycommand.h"
#include "commands/exportsecretsubkeycommand.h"
#include "commands/importpaperkeycommand.h"
#include "commands/keytocardcommand.h"
#include "exportdialog.h"

#include <kleopatra_debug.h>

#include <Libkleo/Compat>
#include <Libkleo/Formatting>
#include <Libkleo/GnuPG>
#include <Libkleo/KeyCache>
#include <Libkleo/KeyHelpers>
#include <Libkleo/TreeWidget>

#include <KConfigGroup>
#include <KLocalizedString>
#include <KSeparator>
#include <KSharedConfig>

#include <QDialogButtonBox>
#include <QHeaderView>
#include <QLabel>
#include <QMenu>
#include <QPushButton>
#include <QTreeWidgetItem>
#include <QVBoxLayout>

#include <QGpgME/CryptoConfig>
#include <QGpgME/Protocol>

#include <gpgme++/context.h>
#include <gpgme++/key.h>

#include <gpgme.h>

Q_DECLARE_METATYPE(GpgME::Subkey)

using namespace Kleo;
using namespace Kleo::Commands;

static QPushButton *addActionButton(QLayout *buttonBox, QAction *action, bool bindVisibility = true)
{
    if (!action) {
        return nullptr;
    }
    auto button = new QPushButton(buttonBox->parentWidget());
    button->setText(action->text());
    buttonBox->addWidget(button);
    button->setEnabled(action->isEnabled());
    QObject::connect(action, &QAction::changed, button, [action, button, bindVisibility]() {
        button->setEnabled(action->isEnabled());
        if (bindVisibility) {
            button->setVisible(action->isVisible());
        }
    });
    QObject::connect(button, &QPushButton::clicked, action, &QAction::trigger);
    return button;
}

class SubKeysWidget::Private
{
    SubKeysWidget *const q;

public:
    enum Columns {
        KeyId,
        Fingerprint,
        Status,
        ValidFrom,
        ValidUntil,
        Usage,
        Algorithm,
        Storage,
        Keygrip,
    };

    Private(SubKeysWidget *qq)
        : q{qq}
        , ui{qq}
    {
        ui.subkeysTree->setContextMenuPolicy(Qt::CustomContextMenu);
        connect(ui.subkeysTree, &QAbstractItemView::customContextMenuRequested, q, [this](const QPoint &p) {
            tableContextMenuRequested(p);
        });
        connect(Kleo::KeyCache::instance().get(), &Kleo::KeyCache::keysMayHaveChanged, q, [this]() {
            keysMayHaveChanged();
        });
        connect(ui.moreButton, &QPushButton::clicked, q, [this]() {
            auto menu = new QMenu(q);
            menu->addAction(ui.exportOpenSSHAction);
            menu->addAction(ui.transferToSmartcardAction);
            menu->addAction(ui.exportSecretAction);
            menu->addAction(ui.restoreAction);
#if GPGME_VERSION_NUMBER >= 0x011800 // 1.24.0
            if (engineIsVersion(2, 4, 6) || (engineIsVersion(2, 2, 45) && !engineIsVersion(2, 3, 0))) {
                menu->addAction(ui.addAdskAction);
            }
#endif
            menu->popup(ui.moreButton->mapToGlobal(QPoint()));
        });
    }

    void changeValidity(const GpgME::Subkey &subkey);
    void exportSSH(const GpgME::Subkey &subkey);
    void keyToCard(const GpgME::Subkey &subkey);
    void exportSecret(const GpgME::Subkey &subkey);
    void importPaperKey();
    void addSubkey();
    void updateState();

private:
    void tableContextMenuRequested(const QPoint &p);
    void keysMayHaveChanged();

public:
    GpgME::Key key;

public:
    struct UI {
        QVBoxLayout *mainLayout;
        TreeWidget *subkeysTree;

        QAction *changeValidityAction = nullptr;
        QAction *transferToSmartcardAction = nullptr;
        QAction *exportSecretAction = nullptr;
        QAction *addSubkeyAction = nullptr;
        QAction *addAdskAction = nullptr;

        QAction *restoreAction = nullptr;
        QPushButton *restoreBtn = nullptr;
        QAction *exportOpenSSHAction = nullptr;
        QPushButton *exportOpenSSHBtn = nullptr;

        QPushButton *moreButton = nullptr;

        UI(QWidget *widget)
        {
            mainLayout = new QVBoxLayout{widget};
            mainLayout->setContentsMargins({});

            subkeysTree = new TreeWidget{widget};
            subkeysTree->setAccessibleName(i18nc("@label", "Subkeys"));
            subkeysTree->setRootIsDecorated(false);
            subkeysTree->setHeaderLabels({
                i18nc("@title:column", "Key ID"),
                i18nc("@title:column", "Fingerprint"),
                i18nc("@title:column", "Status"),
                i18nc("@title:column", "Valid From"),
                i18nc("@title:column", "Valid Until"),
                i18nc("@title:column", "Usage"),
                i18nc("@title:column", "Algorithm"),
                i18nc("@title:column", "Storage"),
                i18nc("@title:column", "Keygrip"),
            });
            mainLayout->addWidget(subkeysTree);

            {
                auto buttonRow = new QHBoxLayout;

                addSubkeyAction = new QAction({}, i18nc("@action:button", "Add subkey"));
                changeValidityAction = new QAction({}, i18nc("@action:button", "Change validity"), widget);
                exportOpenSSHAction = new QAction({}, i18nc("@action:button", "Export OpenSSH key"), widget);
                restoreAction = new QAction({}, i18nc("@action:button", "Restore printed backup"), widget);
                transferToSmartcardAction = new QAction({}, i18nc("@action:button", "Transfer to smartcard"), widget);
                exportSecretAction = new QAction({}, i18nc("@action:button", "Export secret subkey"), widget);
                addAdskAction = new QAction({}, i18nc("@action:button", "Add ADSK"));
                addAdskAction->setToolTip(i18nc("@info:tooltip",
                                                "Add the ADSK specified in the GnuPG configuration to your certificate. By "
                                                "adding an ADSK to your certificate, you allow the owner of the ADSK to decrypt all new messages that "
                                                "are encrypted for your certificate, if the client encrypting the "
                                                "message supports this functionality."));
                addAdskAction->setVisible(false);

                addActionButton(buttonRow, addSubkeyAction);
                addActionButton(buttonRow, changeValidityAction);
                exportOpenSSHBtn = addActionButton(buttonRow, exportOpenSSHAction, false);
                restoreBtn = addActionButton(buttonRow, restoreAction, false);

                moreButton = new QPushButton(QIcon::fromTheme(QStringLiteral("application-menu")), {});
                moreButton->setToolTip(i18nc("@info:tooltip", "Show more options"));
                buttonRow->addWidget(moreButton);
                buttonRow->addStretch(1);

                mainLayout->addLayout(buttonRow);
            }
        }
    } ui;
};

void SubKeysWidget::Private::changeValidity(const GpgME::Subkey &subkey)
{
    ui.changeValidityAction->setEnabled(false);
    auto cmd = new ChangeExpiryCommand(subkey.parent());
    cmd->setSubkey(subkey);
    ui.subkeysTree->setEnabled(false);
    connect(cmd, &ChangeExpiryCommand::finished, q, [this]() {
        ui.subkeysTree->setEnabled(true);
        key.update();
        q->setKey(key);
        ui.changeValidityAction->setEnabled(true);
    });
    cmd->setParentWidget(q);
    cmd->start();
}

void SubKeysWidget::Private::exportSSH(const GpgME::Subkey &subkey)
{
    QScopedPointer<ExportDialog> dlg(new ExportDialog(q));
    dlg->setKey(subkey, static_cast<unsigned int>(GpgME::Context::ExportSSH));
    dlg->exec();
}

void SubKeysWidget::Private::importPaperKey()
{
    ui.restoreAction->setEnabled(false);
    auto cmd = new ImportPaperKeyCommand(key);
    ui.subkeysTree->setEnabled(false);
    connect(cmd, &ImportPaperKeyCommand::finished, q, [this]() {
        ui.subkeysTree->setEnabled(true);
        ui.restoreAction->setEnabled(true);
    });
    cmd->setParentWidget(q);
    cmd->start();
}

void SubKeysWidget::Private::keyToCard(const GpgME::Subkey &subkey)
{
    auto cmd = new KeyToCardCommand(subkey);
    ui.subkeysTree->setEnabled(false);
    connect(cmd, &KeyToCardCommand::finished, q, [this]() {
        ui.subkeysTree->setEnabled(true);
    });
    cmd->setParentWidget(q);
    cmd->start();
}

void SubKeysWidget::Private::exportSecret(const GpgME::Subkey &subkey)
{
    ui.exportSecretAction->setEnabled(false);
    auto cmd = new ExportSecretSubkeyCommand{{subkey}};
    ui.subkeysTree->setEnabled(false);
    connect(cmd, &ExportSecretSubkeyCommand::finished, q, [this]() {
        ui.subkeysTree->setEnabled(true);
        ui.exportSecretAction->setEnabled(true);
    });
    cmd->setParentWidget(q);
    cmd->start();
}

void SubKeysWidget::Private::addSubkey()
{
    ui.addSubkeyAction->setEnabled(false);
    const auto cmd = new AddSubkeyCommand(q->key());
    connect(cmd, &AddSubkeyCommand::finished, q, [this]() {
        q->key().update();
        ui.addSubkeyAction->setEnabled(true);
    });
    cmd->setParentWidget(q);
    cmd->start();
}

void SubKeysWidget::Private::tableContextMenuRequested(const QPoint &p)
{
    auto item = ui.subkeysTree->itemAt(p);
    if (!item) {
        return;
    }
    const auto subkey = item->data(0, Qt::UserRole).value<GpgME::Subkey>();
    const bool isOwnKey = subkey.parent().hasSecret();
    const bool secretSubkeyStoredInKeyRing = subkey.isSecret() && !subkey.isCardKey();

    auto menu = new QMenu(q);
    connect(menu, &QMenu::aboutToHide, menu, &QObject::deleteLater);

    if (isOwnKey) {
        auto action = menu->addAction(QIcon::fromTheme(QStringLiteral("change-date-symbolic")), i18n("Change validity"), q, [this, subkey]() {
            changeValidity(subkey);
        });
        action->setEnabled(canBeUsedForSecretKeyOperations(subkey.parent()));
    }

    if (subkey.canAuthenticate()) {
        menu->addAction(QIcon::fromTheme(QStringLiteral("view-certificate-export")), i18n("Export OpenSSH key"), q, [this, subkey]() {
            exportSSH(subkey);
        });
    }

    if (isOwnKey) {
        auto action = menu->addAction(QIcon::fromTheme(QStringLiteral("send-to-symbolic")), i18n("Transfer to smartcard"), q, [this, subkey]() {
            keyToCard(subkey);
        });
        action->setEnabled(secretSubkeyStoredInKeyRing && !KeyToCardCommand::getSuitableCards(subkey).empty());
    }

    const bool isPrimarySubkey = subkey.keyID() == key.keyID();
    if (isOwnKey && !isPrimarySubkey) {
        auto action = menu->addAction(QIcon::fromTheme(QStringLiteral("view-certificate-export")), i18n("Export secret subkey"), q, [this, subkey]() {
            exportSecret(subkey);
        });
        action->setEnabled(secretSubkeyStoredInKeyRing);
    }

    menu->popup(ui.subkeysTree->viewport()->mapToGlobal(p));
}

void SubKeysWidget::Private::keysMayHaveChanged()
{
    qCDebug(KLEOPATRA_LOG) << q << __func__;
    const auto updatedKey = Kleo::KeyCache::instance()->findByFingerprint(key.primaryFingerprint());
    if (!updatedKey.isNull()) {
        q->setKey(updatedKey);
    }
}

void SubKeysWidget::Private::updateState()
{
    const auto currentIndex = ui.subkeysTree->currentIndex().row();
    const auto &subkey = key.subkey(currentIndex);
    const bool secretSubkeyStoredInKeyRing = subkey.isSecret() && !subkey.isCardKey();
    ui.exportOpenSSHAction->setEnabled(subkey.canAuthenticate());
    ui.changeValidityAction->setEnabled(key.hasSecret() && canBeUsedForSecretKeyOperations(subkey.parent()));
    ui.exportSecretAction->setEnabled(key.hasSecret() && subkey.fingerprint() != key.primaryFingerprint() && secretSubkeyStoredInKeyRing);
    ui.restoreAction->setEnabled(!secretSubkeyStoredInKeyRing);
    ui.transferToSmartcardAction->setEnabled(secretSubkeyStoredInKeyRing && !KeyToCardCommand::getSuitableCards(subkey).empty());
}

SubKeysWidget::SubKeysWidget(QWidget *parent)
    : QWidget(parent)
    , d(new Private(this))
{
    connect(d->ui.subkeysTree, &TreeWidget::currentItemChanged, this, [this] {
        d->updateState();
    });
    connect(d->ui.changeValidityAction, &QAction::triggered, this, [this] {
        d->changeValidity(d->key.subkey(d->ui.subkeysTree->currentIndex().row()));
    });
    connect(d->ui.exportOpenSSHAction, &QAction::triggered, this, [this] {
        d->exportSSH(d->key.subkey(d->ui.subkeysTree->currentIndex().row()));
    });
    connect(d->ui.restoreAction, &QAction::triggered, this, [this] {
        d->importPaperKey();
    });
    connect(d->ui.transferToSmartcardAction, &QAction::triggered, this, [this] {
        d->keyToCard(d->key.subkey(d->ui.subkeysTree->currentIndex().row()));
    });
    connect(d->ui.exportSecretAction, &QAction::triggered, this, [this] {
        d->exportSecret(d->key.subkey(d->ui.subkeysTree->currentIndex().row()));
    });
    connect(d->ui.addSubkeyAction, &QAction::triggered, this, [this]() {
        d->addSubkey();
    });
    connect(d->ui.addAdskAction, &QAction::triggered, this, [this]() {
        auto addADSKCommand = new Kleo::Commands::AddADSKCommand(key());
        addADSKCommand->setParentWidget(this);
        addADSKCommand->start();
    });
}

SubKeysWidget::~SubKeysWidget() = default;

void SubKeysWidget::setKey(const GpgME::Key &key)
{
    if (key.protocol() != GpgME::OpenPGP) {
        return;
    }
    d->key = key;

    const auto currentItem = d->ui.subkeysTree->currentItem();
    const QByteArray selectedKeyFingerprint = currentItem ? QByteArray(currentItem->data(0, Qt::UserRole).value<GpgME::Subkey>().fingerprint()) : QByteArray();
    d->ui.subkeysTree->clear();

    const auto subkeys = key.subkeys();
    for (const auto &subkey : subkeys) {
        auto item = new QTreeWidgetItem;
        item->setData(Private::KeyId, Qt::DisplayRole, Formatting::prettyID(subkey.keyID()));
        item->setData(Private::KeyId, Qt::AccessibleTextRole, Formatting::accessibleHexID(subkey.keyID()));
        item->setData(Private::KeyId, Qt::UserRole, QVariant::fromValue(subkey));
        item->setData(Private::Fingerprint, Qt::DisplayRole, Formatting::prettyID(subkey.fingerprint()));
        item->setData(Private::Fingerprint, Qt::AccessibleTextRole, Formatting::accessibleHexID(subkey.fingerprint()));
        item->setData(Private::Status, Qt::DisplayRole, Kleo::Formatting::validityShort(subkey));
        item->setData(Private::ValidFrom, Qt::DisplayRole, Kleo::Formatting::creationDateString(subkey));
        item->setData(Private::ValidFrom, Qt::AccessibleTextRole, Formatting::accessibleCreationDate(subkey));
        item->setData(Private::ValidUntil,
                      Qt::DisplayRole,
                      subkey.neverExpires() ? Kleo::Formatting::expirationDateString(subkey.parent()) : Kleo::Formatting::expirationDateString(subkey));
        item->setData(Private::ValidUntil,
                      Qt::AccessibleTextRole,
                      subkey.neverExpires() ? Kleo::Formatting::accessibleExpirationDate(subkey.parent()) : Kleo::Formatting::accessibleExpirationDate(subkey));
        item->setData(Private::Usage, Qt::DisplayRole, Kleo::Formatting::usageString(subkey));
        item->setData(Private::Algorithm, Qt::DisplayRole, Kleo::Formatting::prettyAlgorithmName(subkey.algoName()));
        const auto isPrimary = subkey.keyID() == key.keyID();
        if (!key.hasSecret()) {
            item->setData(Private::Storage, Qt::DisplayRole, i18nc("not applicable", "n/a"));
        } else if (subkey.isCardKey()) {
            if (const char *serialNo = subkey.cardSerialNumber()) {
                item->setData(Private::Storage, Qt::DisplayRole, i18nc("smart card <serial number>", "smart card %1", QString::fromUtf8(serialNo)));
            } else {
                item->setData(Private::Storage, Qt::DisplayRole, i18n("smart card"));
            }
        } else if (isPrimary && key.hasSecret() && !subkey.isSecret()) {
            item->setData(Private::Storage, Qt::DisplayRole, i18nc("key is 'offline key', i.e. secret key is not stored on this computer", "offline"));
        } else if (subkey.isSecret()) {
            item->setData(Private::Storage, Qt::DisplayRole, i18n("on this computer"));
        } else {
            item->setData(Private::Storage, Qt::DisplayRole, i18nc("unknown storage location", "unknown"));
        }
        item->setData(Private::Keygrip, Qt::DisplayRole, QString::fromLatin1(subkey.keyGrip()));
        d->ui.subkeysTree->addTopLevelItem(item);
        if (subkey.fingerprint() == selectedKeyFingerprint) {
            d->ui.subkeysTree->setCurrentItem(item);
        }
    }

    d->ui.changeValidityAction->setVisible(key.hasSecret());
    d->ui.exportSecretAction->setVisible(key.hasSecret());
    d->ui.transferToSmartcardAction->setVisible(key.hasSecret());
    d->ui.addSubkeyAction->setVisible(key.hasSecret());
    d->ui.restoreAction->setVisible(true);
    const auto adskConfig = getCryptoConfigEntry(QGpgME::cryptoConfig(), "gpg", "default-new-key-adsk");
    d->ui.addAdskAction->setVisible(key.protocol() == GpgME::OpenPGP && key.hasSecret() && adskConfig && adskConfig->isSet());

    d->ui.exportOpenSSHAction->setEnabled(false);
    d->ui.exportOpenSSHBtn->setVisible(!key.hasSecret());
    d->ui.exportOpenSSHBtn->setEnabled(false);
    d->ui.restoreBtn->setVisible(!key.hasSecret());
    d->ui.moreButton->setVisible(key.hasSecret());

    d->updateState();

    if (!d->ui.subkeysTree->restoreColumnLayout(QStringLiteral("SubkeysWidget"))) {
        d->ui.subkeysTree->hideColumn(Private::KeyId);
        d->ui.subkeysTree->hideColumn(Private::Keygrip);
    }
    d->ui.subkeysTree->resizeToContentsLimited();
}

GpgME::Key SubKeysWidget::key() const
{
    return d->key;
}

#include "moc_subkeyswidget.cpp"
