/*
    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2021 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include "editgroupdialog.h"

#include "commands/detailscommand.h"
#include "utils/gui-helper.h"
#include "view/keytreeview.h"
#include <settings.h>

#include <Libkleo/Algorithm>
#include <Libkleo/Compat>
#include <Libkleo/DefaultKeyFilter>
#include <Libkleo/KeyCache>
#include <Libkleo/KeyFilter>
#include <Libkleo/KeyFilterManager>
#include <Libkleo/KeyHelpers>
#include <Libkleo/KeyListModel>
#include <Libkleo/KeyListSortFilterProxyModel>

#include <KConfigGroup>
#include <KGuiItem>
#include <KLocalizedString>
#include <KSeparator>
#include <KSharedConfig>
#include <KStandardGuiItem>

#include <QApplication>
#include <QComboBox>
#include <QDialogButtonBox>
#include <QGroupBox>
#include <QHBoxLayout>
#include <QItemSelectionModel>
#include <QLabel>
#include <QLineEdit>
#include <QPalette>
#include <QPushButton>
#include <QTreeView>
#include <QVBoxLayout>

#include "kleopatra_debug.h"

using namespace Kleo;
using namespace Kleo::Commands;
using namespace Kleo::Dialogs;
using namespace GpgME;

Q_DECLARE_METATYPE(GpgME::Key)

namespace
{
auto createOpenPGPOnlyKeyFilter()
{
    auto filter = std::make_shared<DefaultKeyFilter>();
    filter->setIsOpenPGP(DefaultKeyFilter::Set);
    return filter;
}
}

namespace
{

class FiltersProxyModel : public QSortFilterProxyModel
{
    Q_OBJECT

public:
    using QSortFilterProxyModel::QSortFilterProxyModel;

protected:
    bool filterAcceptsRow(int sourceRow, const QModelIndex &sourceParent) const override
    {
        const QModelIndex index = sourceModel()->index(sourceRow, 0, sourceParent);
        const auto matchContexts = qvariant_cast<KeyFilter::MatchContexts>(sourceModel()->data(index, KeyFilterManager::FilterMatchContextsRole));
        return matchContexts & KeyFilter::Filtering;
    }
};

}

class WarnNonEncryptionKeysProxyModel : public Kleo::AbstractKeyListSortFilterProxyModel
{
    Q_OBJECT
public:
    enum Mode {
        Warn,
        Disable,
    };

    WarnNonEncryptionKeysProxyModel(Mode mode, QObject *parent = nullptr)
        : AbstractKeyListSortFilterProxyModel(parent)
        , m_mode(mode)
    {
    }

    WarnNonEncryptionKeysProxyModel *clone() const override
    {
        return new WarnNonEncryptionKeysProxyModel(m_mode, parent());
    }

    QVariant data(const QModelIndex &index, int role) const override
    {
        if (!index.isValid()) {
            return {};
        }
        const auto sourceIndex = sourceModel()->index(index.row(), index.column());
        const auto &key = sourceIndex.data(KeyList::KeyRole).value<Key>();
        if (!Kleo::canBeUsedForEncryption(key)) {
            if (role == Qt::DecorationRole && index.column() == KeyList::Columns::Validity) {
                return QIcon::fromTheme(QStringLiteral("data-error"));
            }
            if (role == Qt::DisplayRole && index.column() == KeyList::Columns::Validity) {
                return i18nc("@info as in 'this certificate is unusable'", "unusable");
            }
            if (role == Qt::ToolTipRole) {
                return i18nc("@info:tooltip", "This certificate cannot be used for encryption.");
            }
            if (role == Qt::BackgroundRole || role == Qt::ForegroundRole) {
                return {};
            }
        }
        return sourceIndex.data(role);
    }
    Qt::ItemFlags flags(const QModelIndex &index) const override
    {
        auto originalFlags = index.model()->QAbstractItemModel::flags(index);
        const auto key = index.data(KeyList::KeyRole).value<Key>();
        if (m_mode == Warn || Kleo::canBeUsedForEncryption(key)) {
            return originalFlags;
        } else {
            return (originalFlags & ~Qt::ItemIsEnabled);
        }
        return {};
    }

private:
    Mode m_mode;
};

class EditGroupDialog::Private
{
    friend class ::Kleo::Dialogs::EditGroupDialog;
    EditGroupDialog *const q;

    struct {
        QLineEdit *groupNameEdit = nullptr;
        QLineEdit *availableKeysFilter = nullptr;
        KeyTreeView *availableKeysList = nullptr;
        QLineEdit *groupKeysFilter = nullptr;
        KeyTreeView *groupKeysList = nullptr;
        QDialogButtonBox *buttonBox = nullptr;
        QComboBox *combo = nullptr;
    } ui;
    AbstractKeyListModel *availableKeysModel = nullptr;
    AbstractKeyListModel *groupKeysModel = nullptr;
    KeyGroup keyGroup;
    std::vector<GpgME::Key> oldKeys;
    FiltersProxyModel *filtersProxyModel = nullptr;

public:
    Private(EditGroupDialog *qq)
        : q(qq)
    {
        auto mainLayout = new QVBoxLayout(q);

        {
            auto groupNameLayout = new QHBoxLayout();
            auto label = new QLabel(i18nc("Name of a group of keys", "Name:"), q);
            groupNameLayout->addWidget(label);
            ui.groupNameEdit = new QLineEdit(q);
            label->setBuddy(ui.groupNameEdit);
            groupNameLayout->addWidget(ui.groupNameEdit);
            mainLayout->addLayout(groupNameLayout);
        }

        mainLayout->addWidget(new KSeparator(Qt::Horizontal, q));

        auto centerLayout = new QVBoxLayout;

        auto availableKeysGroupBox = new QGroupBox{i18nc("@title", "Available Certificates"), q};
        availableKeysGroupBox->setFlat(true);
        auto availableKeysLayout = new QVBoxLayout{availableKeysGroupBox};

        {
            auto hbox = new QHBoxLayout;
            auto label = new QLabel{i18nc("@label", "Search:")};
            label->setAccessibleName(i18nc("@label", "Search available certificates"));
            label->setToolTip(i18nc("@info:tooltip", "Search the list of available certificates for any that match the search term."));
            hbox->addWidget(label);

            ui.availableKeysFilter = new QLineEdit(q);
            ui.availableKeysFilter->setClearButtonEnabled(true);
            ui.availableKeysFilter->setAccessibleName(i18nc("@label", "Search available certificates"));
            ui.availableKeysFilter->setToolTip(i18nc("@info:tooltip", "Search the list of available certificates for any that match the search term."));
            ui.availableKeysFilter->setPlaceholderText(i18nc("@info::placeholder", "Enter search term"));
            ui.availableKeysFilter->setCursorPosition(0); // prevent emission of accessible text cursor event before accessible focus event
            label->setBuddy(ui.availableKeysFilter);
            hbox->addWidget(ui.availableKeysFilter, 1);

            ui.combo = new QComboBox;
            ui.combo->setAccessibleName(i18n("Filter certificates by category"));
            ui.combo->setToolTip(i18nc("@info:tooltip", "Show only certificates that belong to the selected category."));

            hbox->addWidget(ui.combo);

            filtersProxyModel = new FiltersProxyModel{q};
            auto keyFilterModel = new KeyFilterModel{q};

            std::shared_ptr<DefaultKeyFilter> filter;
            filter = std::make_shared<DefaultKeyFilter>();
            filter->setCanEncrypt(DefaultKeyFilter::Set);
            filter->setIsBad(DefaultKeyFilter::NotSet);
            filter->setName(i18n("Usable for Encryption"));
            filter->setDescription(i18n("Certificates that can be used for encryption"));
            filter->setId(QStringLiteral("CanEncryptFilter"));
            filter->setMatchContexts(KeyFilter::Filtering);
            keyFilterModel->prependCustomFilter(filter);

            filtersProxyModel->setSourceModel(keyFilterModel);
            filtersProxyModel->sort(0, Qt::AscendingOrder);
            ui.combo->setModel(filtersProxyModel);

            connect(ui.combo, &QComboBox::currentIndexChanged, q, [this](int index) {
                const auto filter =
                    filtersProxyModel->data(filtersProxyModel->index(index, 0), KeyFilterManager::FilterRole).value<std::shared_ptr<KeyFilter>>();
                ui.availableKeysList->setKeyFilter(filter);
            });

            availableKeysLayout->addLayout(hbox);
        }

        availableKeysModel = AbstractKeyListModel::createFlatKeyListModel(q);
        availableKeysModel->setKeys(KeyCache::instance()->keys());
        auto proxyModel = new WarnNonEncryptionKeysProxyModel(WarnNonEncryptionKeysProxyModel::Disable, q);
        proxyModel->setSourceModel(availableKeysModel);
        ui.availableKeysList = new KeyTreeView({}, nullptr, proxyModel, q, {});
        ui.availableKeysList->view()->setAccessibleName(i18nc("@label", "Available certificates"));
        ui.availableKeysList->view()->setRootIsDecorated(false);
        ui.availableKeysList->setFlatModel(availableKeysModel);
        ui.availableKeysList->setHierarchicalView(false);
        if (!Settings{}.cmsEnabled()) {
            ui.availableKeysList->setKeyFilter(createOpenPGPOnlyKeyFilter());
        }
        availableKeysLayout->addWidget(ui.availableKeysList, /*stretch=*/1);

        centerLayout->addWidget(availableKeysGroupBox, /*stretch=*/1);

        auto buttonsLayout = new QHBoxLayout;
        buttonsLayout->addStretch(1);

        auto addButton = new QPushButton(q);
        addButton->setIcon(QIcon::fromTheme(QStringLiteral("arrow-down")));
        addButton->setAccessibleName(i18nc("@action:button", "Add Selected Certificates"));
        addButton->setToolTip(i18nc("@info:tooltip", "Add the selected certificates to the group"));
        addButton->setEnabled(false);
        buttonsLayout->addWidget(addButton);

        auto removeButton = new QPushButton(q);
        removeButton->setIcon(QIcon::fromTheme(QStringLiteral("arrow-up")));
        removeButton->setAccessibleName(i18nc("@action:button", "Remove Selected Certificates"));
        removeButton->setToolTip(i18nc("@info:tooltip", "Remove the selected certificates from the group"));
        removeButton->setEnabled(false);
        buttonsLayout->addWidget(removeButton);

        buttonsLayout->addStretch(1);

        centerLayout->addLayout(buttonsLayout);

        auto groupKeysGroupBox = new QGroupBox{i18nc("@title", "Certificates in the Group"), q};
        groupKeysGroupBox->setFlat(true);
        auto groupKeysLayout = new QVBoxLayout{groupKeysGroupBox};

        {
            auto hbox = new QHBoxLayout;
            auto label = new QLabel{i18nc("@label", "Search:")};
            label->setAccessibleName(i18nc("@label", "Search for certificates in the group"));
            label->setToolTip(i18nc("@info:tooltip", "Search the list of certificates in the group for any that match the search term."));
            hbox->addWidget(label);

            ui.groupKeysFilter = new QLineEdit(q);
            ui.groupKeysFilter->setClearButtonEnabled(true);
            ui.groupKeysFilter->setAccessibleName(i18nc("@label", "Search for certificates in the group"));
            ui.groupKeysFilter->setToolTip(i18nc("@info:tooltip", "Search the list of certificates in the group for any that match the search term."));
            ui.groupKeysFilter->setPlaceholderText(i18nc("@info::placeholder", "Enter search term"));
            ui.groupKeysFilter->setCursorPosition(0); // prevent emission of accessible text cursor event before accessible focus event
            label->setBuddy(ui.groupKeysFilter);
            hbox->addWidget(ui.groupKeysFilter, 1);

            groupKeysLayout->addLayout(hbox);
        }

        groupKeysModel = AbstractKeyListModel::createFlatKeyListModel(q);

        auto warnNonEncryptionProxyModel = new WarnNonEncryptionKeysProxyModel(WarnNonEncryptionKeysProxyModel::Warn, q);
        ui.groupKeysList = new KeyTreeView({}, nullptr, warnNonEncryptionProxyModel, q, {});
        ui.groupKeysList->view()->setAccessibleName(i18nc("@label", "Certificates in group"));
        ui.groupKeysList->view()->setRootIsDecorated(false);
        ui.groupKeysList->setFlatModel(groupKeysModel);
        ui.groupKeysList->setHierarchicalView(false);
        groupKeysLayout->addWidget(ui.groupKeysList, /*stretch=*/1);

        centerLayout->addWidget(groupKeysGroupBox, /*stretch=*/1);

        mainLayout->addLayout(centerLayout);

        mainLayout->addWidget(new KSeparator(Qt::Horizontal, q));

        ui.buttonBox = new QDialogButtonBox(QDialogButtonBox::Save | QDialogButtonBox::Cancel, q);
        QPushButton *saveButton = ui.buttonBox->button(QDialogButtonBox::Save);
        KGuiItem::assign(saveButton, KStandardGuiItem::save());
        KGuiItem::assign(ui.buttonBox->button(QDialogButtonBox::Cancel), KStandardGuiItem::cancel());
        saveButton->setEnabled(false);
        mainLayout->addWidget(ui.buttonBox);

        // prevent accidental closing of dialog when pressing Enter while a search field has focus
        Kleo::unsetAutoDefaultButtons(q);

        connect(ui.groupNameEdit, &QLineEdit::textChanged, q, [saveButton](const QString &text) {
            saveButton->setEnabled(!text.trimmed().isEmpty());
        });
        connect(ui.availableKeysFilter, &QLineEdit::textChanged, ui.availableKeysList, &KeyTreeView::setStringFilter);
        connect(ui.availableKeysList->view()->selectionModel(),
                &QItemSelectionModel::selectionChanged,
                q,
                [addButton, this](const QItemSelection &, const QItemSelection &) {
                    addButton->setEnabled(ui.availableKeysList->selectedKeys().size() > 0);
                });
        connect(ui.availableKeysList->view(), &QAbstractItemView::doubleClicked, q, [this](const QModelIndex &index) {
            showKeyDetails(index);
        });
        connect(ui.groupKeysFilter, &QLineEdit::textChanged, ui.groupKeysList, &KeyTreeView::setStringFilter);
        connect(ui.groupKeysList->view()->selectionModel(),
                &QItemSelectionModel::selectionChanged,
                q,
                [removeButton](const QItemSelection &selected, const QItemSelection &) {
                    removeButton->setEnabled(!selected.isEmpty());
                });
        connect(ui.groupKeysList->view(), &QAbstractItemView::doubleClicked, q, [this](const QModelIndex &index) {
            showKeyDetails(index);
        });
        connect(addButton, &QPushButton::clicked, q, [this]() {
            addKeysToGroup();
        });
        connect(removeButton, &QPushButton::clicked, q, [this]() {
            removeKeysFromGroup();
        });
        connect(ui.buttonBox, &QDialogButtonBox::accepted, q, &EditGroupDialog::accept);
        connect(ui.buttonBox, &QDialogButtonBox::rejected, q, &EditGroupDialog::reject);

        connect(KeyCache::instance().get(), &KeyCache::keysMayHaveChanged, q, [this] {
            updateFromKeyCache();
        });

        // calculate default size with enough space for the key list
        const auto fm = q->fontMetrics();
        const QSize sizeHint = q->sizeHint();
        const QSize defaultSize = QSize(qMax(sizeHint.width(), 150 * fm.horizontalAdvance(QLatin1Char('x'))), sizeHint.height());
        restoreLayout(defaultSize);

        for (auto i = 0; i < filtersProxyModel->rowCount(); ++i) {
            if (filtersProxyModel->index(i, 0).data(KeyFilterManager::FilterIdRole).toString() == QLatin1StringView("CanEncryptFilter")) {
                ui.combo->setCurrentIndex(i);
                break;
            };
        }
    }

    ~Private()
    {
        saveLayout();
    }

private:
    void saveLayout()
    {
        KConfigGroup configGroup(KSharedConfig::openConfig(), QStringLiteral("EditGroupDialog"));
        configGroup.writeEntry("Size", q->size());

        configGroup.sync();
    }

    void restoreLayout(const QSize &defaultSize)
    {
        const KConfigGroup configGroup(KSharedConfig::openConfig(), QStringLiteral("EditGroupDialog"));

        const KConfigGroup availableKeysConfig = configGroup.group(QStringLiteral("AvailableKeysView"));
        ui.availableKeysList->restoreLayout(availableKeysConfig);

        const KConfigGroup groupKeysConfig = configGroup.group(QStringLiteral("GroupKeysView"));
        ui.groupKeysList->restoreLayout(groupKeysConfig);

        const QSize size = configGroup.readEntry("Size", defaultSize);
        if (size.isValid()) {
            q->resize(size);
        }
    }

    void showKeyDetails(const QModelIndex &index)
    {
        if (!index.isValid()) {
            return;
        }
        const auto key = index.model()->data(index, KeyList::KeyRole).value<GpgME::Key>();
        if (!key.isNull()) {
            auto cmd = new DetailsCommand(key);
            cmd->setParentWidget(q);
            cmd->start();
        }
    }

    void addKeysToGroup();
    void removeKeysFromGroup();
    void updateFromKeyCache();
};

void EditGroupDialog::Private::addKeysToGroup()
{
    const std::vector<Key> selectedGroupKeys = ui.groupKeysList->selectedKeys();

    std::vector<Key> selectedKeys = ui.availableKeysList->selectedKeys();

    // NOTE: This seems to be only necessary on Qt5. I've added it here for ease
    // of backporting. We can remove it after backporting.
    Kleo::erase_if(selectedKeys, [](const auto &key) {
        return !Kleo::canBeUsedForEncryption(key);
    });

    groupKeysModel->addKeys(selectedKeys);
    for (const Key &key : selectedKeys) {
        availableKeysModel->removeKey(key);
    }

    ui.groupKeysList->selectKeys(selectedGroupKeys);
}

void EditGroupDialog::Private::removeKeysFromGroup()
{
    const auto selectedOtherKeys = ui.availableKeysList->selectedKeys();

    const std::vector<Key> selectedKeys = ui.groupKeysList->selectedKeys();
    for (const Key &key : selectedKeys) {
        groupKeysModel->removeKey(key);
    }
    availableKeysModel->addKeys(selectedKeys);

    ui.availableKeysList->selectKeys(selectedOtherKeys);
}

void EditGroupDialog::Private::updateFromKeyCache()
{
    const auto selectedGroupKeys = ui.groupKeysList->selectedKeys();
    const auto selectedOtherKeys = ui.availableKeysList->selectedKeys();

    const auto wasGroupKey = [this](const Key &key) {
        return std::ranges::any_of(oldKeys, [key](const auto &k) {
            return _detail::ByFingerprint<std::equal_to>()(k, key);
        });
    };
    const auto allKeys = KeyCache::instance()->keys();
    std::vector<Key> groupKeys;
    groupKeys.reserve(allKeys.size());
    std::vector<Key> otherKeys;
    otherKeys.reserve(otherKeys.size());
    std::partition_copy(allKeys.begin(), allKeys.end(), std::back_inserter(groupKeys), std::back_inserter(otherKeys), wasGroupKey);
    groupKeysModel->setKeys(groupKeys);
    availableKeysModel->setKeys(otherKeys);

    ui.groupKeysList->selectKeys(selectedGroupKeys);
    ui.availableKeysList->selectKeys(selectedOtherKeys);
}

EditGroupDialog::EditGroupDialog(QWidget *parent)
    : QDialog(parent)
    , d(new Private(this))
{
    setWindowTitle(i18nc("@title:window", "Edit Group"));
}

EditGroupDialog::~EditGroupDialog() = default;

void EditGroupDialog::setInitialFocus(FocusWidget widget)
{
    switch (widget) {
    case GroupName:
        d->ui.groupNameEdit->setFocus();
        break;
    case KeysFilter:
        d->ui.availableKeysFilter->setFocus();
        break;
    default:
        qCDebug(KLEOPATRA_LOG) << "EditGroupDialog::setInitialFocus - invalid focus widget:" << widget;
    }
}

void EditGroupDialog::showEvent(QShowEvent *event)
{
    QDialog::showEvent(event);

    // prevent accidental closing of dialog when pressing Enter while a search field has focus
    Kleo::unsetDefaultButtons(d->ui.buttonBox);
}

KeyGroup EditGroupDialog::keyGroup() const
{
    std::vector<Key> keys;
    keys.reserve(d->groupKeysModel->rowCount());
    for (int row = 0; row < d->groupKeysModel->rowCount(); ++row) {
        const QModelIndex index = d->groupKeysModel->index(row, 0);
        keys.push_back(d->groupKeysModel->key(index));
    }
    d->keyGroup.setKeys(keys);

    d->keyGroup.setName(d->ui.groupNameEdit->text().trimmed());
    return d->keyGroup;
}

void EditGroupDialog::setKeyGroup(const KeyGroup &keyGroup)
{
    d->keyGroup = keyGroup;

    const auto &keys = keyGroup.keys();
    d->oldKeys = std::vector<GpgME::Key>(keys.begin(), keys.end());
    d->groupKeysModel->setKeys(d->oldKeys);

    // update the keys in the "available keys" list
    const auto isGroupKey = [keys](const Key &key) {
        return std::ranges::any_of(keys, [key](const auto &k) {
            return _detail::ByFingerprint<std::equal_to>()(k, key);
        });
    };
    auto otherKeys = KeyCache::instance()->keys();
    Kleo::erase_if(otherKeys, isGroupKey);
    d->availableKeysModel->setKeys(otherKeys);

    d->ui.groupNameEdit->setText(keyGroup.name());
}

#include "editgroupdialog.moc"
#include "moc_editgroupdialog.cpp"
