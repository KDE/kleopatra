/* -*- mode: c++; c-basic-offset:4 -*-
    view/keytreeview.cpp

    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2009 Klarälvdalens Datakonsult AB

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include <config-kleopatra.h>

#include "keytreeview.h"
#include "searchbar.h"

#include <Libkleo/KeyList>
#include <Libkleo/KeyListModel>
#include <Libkleo/KeyListSortFilterProxyModel>
#include <Libkleo/KeyRearrangeColumnsProxyModel>
#include <Libkleo/Predicates>
#include <Libkleo/TreeView>

#include "utils/headerview.h"
#include "utils/tags.h"

#include <Libkleo/KeyCache>
#include <Libkleo/KeyFilter>
#include <Libkleo/Stl_Util>

#include <gpgme++/key.h>

#include "kleopatra_debug.h"
#include <QAction>
#include <QContextMenuEvent>
#include <QEvent>
#include <QHeaderView>
#include <QItemSelection>
#include <QItemSelectionModel>
#include <QLayout>
#include <QList>
#include <QMenu>
#include <QTimer>

#include <KLocalizedString>
#include <KSharedConfig>

static int tagsColumn;

using namespace Kleo;
using namespace GpgME;

Q_DECLARE_METATYPE(GpgME::Key)

namespace
{

class TreeViewInternal : public Kleo::TreeView
{
public:
    explicit TreeViewInternal(QWidget *parent = nullptr)
        : Kleo::TreeView{parent}
    {
        connect(this, &TreeView::columnEnabled, this, [this](int column) {
            if (column == tagsColumn) {
                Tags::enableTags();
            }
        });
    }

    QSize minimumSizeHint() const override
    {
        const QSize min = QTreeView::minimumSizeHint();
        return QSize(min.width(), min.height() + 5 * fontMetrics().height());
    }

private:
    QMenu *mHeaderPopup = nullptr;

    QList<QAction *> mColumnActions;
};

const KeyListModelInterface *keyListModel(const QTreeView &view)
{
    const KeyListModelInterface *const klmi = dynamic_cast<KeyListModelInterface *>(view.model());
    Q_ASSERT(klmi);
    return klmi;
}

} // anon namespace

KeyTreeView::KeyTreeView(QWidget *parent)
    : QWidget(parent)
    , m_proxy(new KeyListSortFilterProxyModel(this))
    , m_additionalProxy(nullptr)
    , m_view(new TreeViewInternal(this))
    , m_flatModel(nullptr)
    , m_hierarchicalModel(nullptr)
    , m_stringFilter()
    , m_keyFilter()
    , m_isHierarchical(true)
{
    init();
}

KeyTreeView::KeyTreeView(const KeyTreeView &other)
    : QWidget(nullptr)
    , m_proxy(new KeyListSortFilterProxyModel(this))
    , m_additionalProxy(other.m_additionalProxy ? other.m_additionalProxy->clone() : nullptr)
    , m_view(new TreeViewInternal(this))
    , m_flatModel(other.m_flatModel)
    , m_hierarchicalModel(other.m_hierarchicalModel)
    , m_stringFilter(other.m_stringFilter)
    , m_keyFilter(other.m_keyFilter)
    , m_group(other.m_group)
    , m_isHierarchical(other.m_isHierarchical)
{
    init();
    setColumnSizes(other.columnSizes());
    setSortColumn(other.sortColumn(), other.sortOrder());
}

KeyTreeView::KeyTreeView(const QString &text,
                         const std::shared_ptr<KeyFilter> &kf,
                         AbstractKeyListSortFilterProxyModel *proxy,
                         QWidget *parent,
                         const KConfigGroup &group)
    : QWidget(parent)
    , m_proxy(new KeyListSortFilterProxyModel(this))
    , m_additionalProxy(proxy)
    , m_view(new TreeViewInternal(this))
    , m_flatModel(nullptr)
    , m_hierarchicalModel(nullptr)
    , m_stringFilter(text)
    , m_keyFilter(kf)
    , m_group(group)
    , m_isHierarchical(true)
    , m_onceResized(false)
{
    init();
}

void KeyTreeView::setColumnSizes(const std::vector<int> &sizes)
{
    if (sizes.empty()) {
        return;
    }
    Q_ASSERT(m_view);
    Q_ASSERT(m_view->header());
    Q_ASSERT(qobject_cast<HeaderView *>(m_view->header()) == static_cast<HeaderView *>(m_view->header()));
    if (auto const hv = static_cast<HeaderView *>(m_view->header())) {
        hv->setSectionSizes(sizes);
    }
}

void KeyTreeView::setSortColumn(int sortColumn, Qt::SortOrder sortOrder)
{
    Q_ASSERT(m_view);
    m_view->sortByColumn(sortColumn, sortOrder);
}

int KeyTreeView::sortColumn() const
{
    Q_ASSERT(m_view);
    Q_ASSERT(m_view->header());
    return m_view->header()->sortIndicatorSection();
}

Qt::SortOrder KeyTreeView::sortOrder() const
{
    Q_ASSERT(m_view);
    Q_ASSERT(m_view->header());
    return m_view->header()->sortIndicatorOrder();
}

std::vector<int> KeyTreeView::columnSizes() const
{
    Q_ASSERT(m_view);
    Q_ASSERT(m_view->header());
    Q_ASSERT(qobject_cast<HeaderView *>(m_view->header()) == static_cast<HeaderView *>(m_view->header()));
    if (auto const hv = static_cast<HeaderView *>(m_view->header())) {
        return hv->sectionSizes();
    } else {
        return std::vector<int>();
    }
}

void KeyTreeView::restoreLayout(const KConfigGroup &group)
{
    if (!group.isValid() || !m_view->restoreColumnLayout(group.name())) {
        // if config is empty then use default settings
        // The numbers have to be in line with the order in
        // setsSourceColumns above
        m_view->hideColumn(5);

        for (int i = 7; i < m_view->model()->columnCount(); ++i) {
            m_view->hideColumn(i);
        }
        if (KeyCache::instance()->initialized()) {
            QTimer::singleShot(0, this, &KeyTreeView::initializeColumnSizes);
        }
    } else {
        m_onceResized = true;
    }
    if (!m_view->isColumnHidden(tagsColumn)) {
        Tags::enableTags();
    }
}

void KeyTreeView::init()
{
    Q_SET_OBJECT_NAME(m_proxy);
    Q_SET_OBJECT_NAME(m_view);

    if (m_group.isValid()) {
        // Reopen as non const
        KConfig *conf = m_group.config();
        m_group = conf->group(m_group.name());
    }

    if (m_additionalProxy && m_additionalProxy->objectName().isEmpty()) {
        Q_SET_OBJECT_NAME(m_additionalProxy);
    }
    QLayout *layout = new QVBoxLayout(this);
    Q_SET_OBJECT_NAME(layout);
    layout->setContentsMargins(0, 0, 0, 0);
    layout->addWidget(m_view);

    auto headerView = new HeaderView(Qt::Horizontal);
    Q_SET_OBJECT_NAME(headerView);
    headerView->installEventFilter(m_view);
    headerView->setSectionsMovable(true);
    m_view->setHeader(headerView);

    m_view->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_view->setSelectionMode(QAbstractItemView::ExtendedSelection);
    m_view->setAllColumnsShowFocus(false);
    m_view->setSortingEnabled(true);
    m_view->setAccessibleName(i18n("Certificates"));
    m_view->setAccessibleDescription(m_isHierarchical ? i18n("Hierarchical list of certificates") : i18n("List of certificates"));
    // we show details on double-click
    m_view->setExpandsOnDoubleClick(false);

    if (model()) {
        if (m_additionalProxy) {
            m_additionalProxy->setSourceModel(model());
        } else {
            m_proxy->setSourceModel(model());
        }
    }
    if (m_additionalProxy) {
        m_proxy->setSourceModel(m_additionalProxy);
        if (!m_additionalProxy->parent()) {
            m_additionalProxy->setParent(this);
        }
    }

    m_proxy->setFilterRegularExpression(QRegularExpression::escape(m_stringFilter.trimmed()));
    m_proxy->setKeyFilter(m_keyFilter);
    m_proxy->setSortCaseSensitivity(Qt::CaseInsensitive);

    auto rearangingModel = new KeyRearrangeColumnsProxyModel(this);
    rearangingModel->setSourceModel(m_proxy);
    QVector<int> columns = {
        KeyList::PrettyName,
        KeyList::PrettyEMail,
        KeyList::Validity,
        KeyList::ValidFrom,
        KeyList::ValidUntil,
        KeyList::TechnicalDetails,
        KeyList::KeyID,
        KeyList::Fingerprint,
        KeyList::OwnerTrust,
        KeyList::Origin,
        KeyList::LastUpdate,
        KeyList::Issuer,
        KeyList::SerialNumber,
        KeyList::Remarks,
        KeyList::Algorithm,
        KeyList::Keygrip,
    };
    tagsColumn = columns.indexOf(KeyList::Remarks);
    rearangingModel->setSourceColumns(columns);
    m_view->setModel(rearangingModel);

    /* Handle expansion state */
    if (m_group.isValid()) {
        m_expandedKeys = m_group.readEntry("Expanded", QStringList());
    }

    connect(m_view, &QTreeView::expanded, this, [this](const QModelIndex &index) {
        if (!index.isValid()) {
            return;
        }
        const auto &key = index.data(KeyList::KeyRole).value<GpgME::Key>();
        if (key.isNull()) {
            return;
        }
        const auto fpr = QString::fromLatin1(key.primaryFingerprint());

        if (m_expandedKeys.contains(fpr)) {
            return;
        }
        m_expandedKeys << fpr;
        if (m_group.isValid()) {
            m_group.writeEntry("Expanded", m_expandedKeys);
        }
    });

    connect(m_view, &QTreeView::collapsed, this, [this](const QModelIndex &index) {
        if (!index.isValid()) {
            return;
        }
        const auto &key = index.data(KeyList::KeyRole).value<GpgME::Key>();
        if (key.isNull()) {
            return;
        }
        m_expandedKeys.removeAll(QString::fromLatin1(key.primaryFingerprint()));
        if (m_group.isValid()) {
            m_group.writeEntry("Expanded", m_expandedKeys);
        }
    });

    updateModelConnections(nullptr, model());
}

void KeyTreeView::restoreExpandState()
{
    if (!KeyCache::instance()->initialized()) {
        qCWarning(KLEOPATRA_LOG) << "Restore expand state before keycache available. Aborting.";
        return;
    }
    for (const auto &fpr : std::as_const(m_expandedKeys)) {
        const KeyListModelInterface *const km = keyListModel(*m_view);
        if (!km) {
            qCWarning(KLEOPATRA_LOG) << "invalid model";
            return;
        }
        const auto key = KeyCache::instance()->findByFingerprint(fpr.toLatin1().constData());
        if (key.isNull()) {
            qCDebug(KLEOPATRA_LOG) << "Cannot find:" << fpr << "anymore in cache";
            m_expandedKeys.removeAll(fpr);
            return;
        }
        const auto idx = km->index(key);
        if (!idx.isValid()) {
            qCDebug(KLEOPATRA_LOG) << "Cannot find:" << fpr << "anymore in model";
            m_expandedKeys.removeAll(fpr);
            return;
        }
        m_view->expand(idx);
    }
}

void KeyTreeView::setUpTagKeys()
{
    const auto tagKeys = Tags::tagKeys();
    if (m_hierarchicalModel) {
        m_hierarchicalModel->setRemarkKeys(tagKeys);
    }
    if (m_flatModel) {
        m_flatModel->setRemarkKeys(tagKeys);
    }
}

KeyTreeView::~KeyTreeView() = default;

static QAbstractProxyModel *find_last_proxy(QAbstractProxyModel *pm)
{
    Q_ASSERT(pm);
    while (auto const sm = qobject_cast<QAbstractProxyModel *>(pm->sourceModel())) {
        pm = sm;
    }
    return pm;
}

void KeyTreeView::updateModelConnections(AbstractKeyListModel *oldModel, AbstractKeyListModel *newModel)
{
    if (oldModel == newModel) {
        return;
    }
    if (oldModel) {
        disconnect(oldModel, &QAbstractItemModel::modelAboutToBeReset, this, &KeyTreeView::saveStateBeforeModelChange);
        disconnect(oldModel, &QAbstractItemModel::modelReset, this, &KeyTreeView::restoreStateAfterModelChange);
        disconnect(oldModel, &QAbstractItemModel::rowsAboutToBeInserted, this, &KeyTreeView::saveStateBeforeModelChange);
        disconnect(oldModel, &QAbstractItemModel::rowsInserted, this, &KeyTreeView::restoreStateAfterModelChange);
        disconnect(oldModel, &QAbstractItemModel::rowsAboutToBeRemoved, this, &KeyTreeView::saveStateBeforeModelChange);
        disconnect(oldModel, &QAbstractItemModel::rowsRemoved, this, &KeyTreeView::restoreStateAfterModelChange);
    }
    if (newModel) {
        connect(newModel, &QAbstractItemModel::modelAboutToBeReset, this, &KeyTreeView::saveStateBeforeModelChange);
        connect(newModel, &QAbstractItemModel::modelReset, this, &KeyTreeView::restoreStateAfterModelChange);
        connect(newModel, &QAbstractItemModel::rowsAboutToBeInserted, this, &KeyTreeView::saveStateBeforeModelChange);
        connect(newModel, &QAbstractItemModel::rowsInserted, this, &KeyTreeView::restoreStateAfterModelChange);
        connect(newModel, &QAbstractItemModel::rowsAboutToBeRemoved, this, &KeyTreeView::saveStateBeforeModelChange);
        connect(newModel, &QAbstractItemModel::rowsRemoved, this, &KeyTreeView::restoreStateAfterModelChange);
    }
}

void KeyTreeView::setFlatModel(AbstractKeyListModel *model)
{
    if (model == m_flatModel) {
        return;
    }
    auto oldModel = m_flatModel;
    m_flatModel = model;
    if (!m_isHierarchical)
    // TODO: this fails when called after setHierarchicalView( false )...
    {
        find_last_proxy(m_proxy)->setSourceModel(model);
        updateModelConnections(oldModel, model);
    }
}

void KeyTreeView::setHierarchicalModel(AbstractKeyListModel *model)
{
    if (model == m_hierarchicalModel) {
        return;
    }
    auto oldModel = m_hierarchicalModel;
    m_hierarchicalModel = model;
    if (m_isHierarchical) {
        find_last_proxy(m_proxy)->setSourceModel(model);
        updateModelConnections(oldModel, model);
        m_view->expandAll();
        for (int column = 0; column < m_view->header()->count(); ++column) {
            m_view->header()->resizeSection(column, qMax(m_view->header()->sectionSize(column), m_view->header()->sectionSizeHint(column)));
        }
    }
}

void KeyTreeView::setStringFilter(const QString &filter)
{
    if (filter == m_stringFilter) {
        return;
    }
    m_stringFilter = filter;
    m_proxy->setFilterRegularExpression(QRegularExpression::escape(filter.trimmed()));
    Q_EMIT stringFilterChanged(filter);
}

void KeyTreeView::setKeyFilter(const std::shared_ptr<KeyFilter> &filter)
{
    if (filter == m_keyFilter || (filter && m_keyFilter && filter->id() == m_keyFilter->id())) {
        return;
    }
    m_keyFilter = filter;
    m_proxy->setKeyFilter(filter);
    Q_EMIT keyFilterChanged(filter);
}

namespace
{
QItemSelection itemSelectionFromKeys(const std::vector<Key> &keys, const QTreeView &view)
{
    const QModelIndexList indexes = keyListModel(view)->indexes(keys);
    return std::accumulate(indexes.cbegin(), indexes.cend(), QItemSelection(), [](QItemSelection selection, const QModelIndex &index) {
        if (index.isValid()) {
            selection.merge(QItemSelection(index, index), QItemSelectionModel::Select);
        }
        return selection;
    });
}
}

void KeyTreeView::selectKeys(const std::vector<Key> &keys)
{
    m_view->selectionModel()->select(itemSelectionFromKeys(keys, *m_view), QItemSelectionModel::ClearAndSelect | QItemSelectionModel::Rows);
}

std::vector<Key> KeyTreeView::selectedKeys() const
{
    return keyListModel(*m_view)->keys(m_view->selectionModel()->selectedRows());
}

void KeyTreeView::setHierarchicalView(bool on)
{
    if (on == m_isHierarchical) {
        return;
    }
    if (on && !hierarchicalModel()) {
        qCWarning(KLEOPATRA_LOG) << "hierarchical view requested, but no hierarchical model set";
        return;
    }
    if (!on && !flatModel()) {
        qCWarning(KLEOPATRA_LOG) << "flat view requested, but no flat model set";
        return;
    }
    const std::vector<Key> selectedKeys = this->selectedKeys();
    const Key currentKey = keyListModel(*m_view)->key(m_view->currentIndex());

    auto oldModel = model();
    m_isHierarchical = on;
    find_last_proxy(m_proxy)->setSourceModel(model());
    updateModelConnections(oldModel, model());
    if (on) {
        m_view->expandAll();
    }
    selectKeys(selectedKeys);
    if (!currentKey.isNull()) {
        const QModelIndex currentIndex = keyListModel(*m_view)->index(currentKey);
        if (currentIndex.isValid()) {
            m_view->selectionModel()->setCurrentIndex(currentIndex, QItemSelectionModel::NoUpdate);
            m_view->scrollTo(currentIndex);
        }
    }
    m_view->setAccessibleDescription(m_isHierarchical ? i18n("Hierarchical list of certificates") : i18n("List of certificates"));
    Q_EMIT hierarchicalChanged(on);
}

void KeyTreeView::setKeys(const std::vector<Key> &keys, const std::vector<Key::Origin> &extraOrigins)
{
    std::vector<Key> sorted = keys;

    if (extraOrigins.empty()) {
        _detail::sort_by_fpr(sorted);
        _detail::remove_duplicates_by_fpr(sorted);
    }
    m_keys = sorted;
    if (m_flatModel) {
        m_flatModel->setKeys(sorted, extraOrigins);
    }
    if (m_hierarchicalModel) {
        m_hierarchicalModel->setKeys(sorted, extraOrigins);
    }
}

void KeyTreeView::addKeysImpl(const std::vector<Key> &keys, bool select)
{
    if (keys.empty()) {
        return;
    }
    if (m_keys.empty()) {
        setKeys(keys);
        return;
    }

    std::vector<Key> sorted = keys;
    _detail::sort_by_fpr(sorted);
    _detail::remove_duplicates_by_fpr(sorted);

    std::vector<Key> newKeys = _detail::union_by_fpr(sorted, m_keys);
    m_keys.swap(newKeys);

    if (m_flatModel) {
        m_flatModel->addKeys(sorted);
    }
    if (m_hierarchicalModel) {
        m_hierarchicalModel->addKeys(sorted);
    }

    if (select) {
        selectKeys(sorted);
    }
}

void KeyTreeView::addKeysSelected(const std::vector<Key> &keys)
{
    addKeysImpl(keys, true);
}

void KeyTreeView::addKeysUnselected(const std::vector<Key> &keys)
{
    addKeysImpl(keys, false);
}

void KeyTreeView::removeKeys(const std::vector<Key> &keys)
{
    if (keys.empty()) {
        return;
    }
    std::vector<Key> sorted = keys;
    _detail::sort_by_fpr(sorted);
    _detail::remove_duplicates_by_fpr(sorted);
    std::vector<Key> newKeys;
    newKeys.reserve(m_keys.size());
    std::set_difference(m_keys.begin(), m_keys.end(), sorted.begin(), sorted.end(), std::back_inserter(newKeys), _detail::ByFingerprint<std::less>());
    m_keys.swap(newKeys);

    if (m_flatModel) {
        std::for_each(sorted.cbegin(), sorted.cend(), [this](const Key &key) {
            m_flatModel->removeKey(key);
        });
    }
    if (m_hierarchicalModel) {
        std::for_each(sorted.cbegin(), sorted.cend(), [this](const Key &key) {
            m_hierarchicalModel->removeKey(key);
        });
    }
}

void KeyTreeView::disconnectSearchBar()
{
    for (const auto &connection : m_connections) {
        disconnect(connection);
    }
    m_connections.clear();
}

bool KeyTreeView::connectSearchBar(const SearchBar *bar)
{
    m_connections.reserve(4);
    m_connections.push_back(connect(this, &KeyTreeView::stringFilterChanged, bar, &SearchBar::setStringFilter));
    m_connections.push_back(connect(bar, &SearchBar::stringFilterChanged, this, &KeyTreeView::setStringFilter));
    m_connections.push_back(connect(this, &KeyTreeView::keyFilterChanged, bar, &SearchBar::setKeyFilter));
    m_connections.push_back(connect(bar, &SearchBar::keyFilterChanged, this, &KeyTreeView::setKeyFilter));

    return std::all_of(m_connections.cbegin(), m_connections.cend(), [](const QMetaObject::Connection &conn) {
        return conn;
    });
}

void KeyTreeView::initializeColumnSizes()
{
    if (m_onceResized || m_view->model()->rowCount() == 0) {
        return;
    }
    m_onceResized = true;
    m_view->resizeToContentsLimited();

    m_view->setColumnWidth(KeyList::PrettyName, 260);
    m_view->setColumnWidth(KeyList::PrettyEMail, 260);
}

void KeyTreeView::saveStateBeforeModelChange()
{
    m_currentKey = keyListModel(*m_view)->key(m_view->currentIndex());
    m_selectedKeys = selectedKeys();
}

void KeyTreeView::restoreStateAfterModelChange()
{
    restoreExpandState();

    selectKeys(m_selectedKeys);
    if (!m_currentKey.isNull()) {
        const QModelIndex currentIndex = keyListModel(*m_view)->index(m_currentKey);
        if (currentIndex.isValid()) {
            m_view->selectionModel()->setCurrentIndex(currentIndex, QItemSelectionModel::NoUpdate);
            m_view->scrollTo(currentIndex);
        }
    }

    setUpTagKeys();
    initializeColumnSizes();
}
