/* -*- mode: c++; c-basic-offset:4 -*-
    view/tabwidget.cpp

    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2007 Klarälvdalens Datakonsult AB

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include <config-kleopatra.h>

#include "tabwidget.h"

#include "kleopatra_debug.h"
#include "searchbar.h"

#include <settings.h>

#include <utils/action_data.h>

#include <Libkleo/KeyFilter>
#include <Libkleo/KeyFilterManager>
#include <Libkleo/KeyListModel>
#include <Libkleo/KeyListSortFilterProxyModel>
#include <Libkleo/Stl_Util>
#include <Libkleo/UserIDProxyModel>

#include <gpgme++/key.h>
// needed for GPGME_VERSION_NUMBER
#include <gpgme.h>

#include <KActionCollection>
#include <KConfig>
#include <KConfigGroup>
#include <KLocalizedString>
#include <QAction>
#include <QInputDialog>
#include <QTabWidget>

#include <QAbstractProxyModel>
#include <QHeaderView>
#include <QMenu>
#include <QRegularExpression>
#include <QTimer>
#include <QToolButton>
#include <QTreeView>
#include <QVBoxLayout>

#include <map>

using namespace Kleo;
using namespace GpgME;

namespace
{

class Page : public Kleo::KeyTreeView
{
    Q_OBJECT
    Page(const Page &other);

public:
    Page(const QString &title,
         const QString &id,
         const QString &text,
         AbstractKeyListSortFilterProxyModel *proxy = nullptr,
         const QString &toolTip = QString(),
         QWidget *parent = nullptr,
         const KConfigGroup &group = KConfigGroup(),
         KeyTreeView::Options options = KeyTreeView::Default);
    Page(const KConfigGroup &group, KeyTreeView::Options options = KeyTreeView::Default, QWidget *parent = nullptr);
    ~Page() override;

    void setTemporary(bool temporary);
    bool isTemporary() const
    {
        return m_isTemporary;
    }

    void setHierarchicalView(bool hierarchical) override;
    void setStringFilter(const QString &filter) override;
    void setKeyFilter(const std::shared_ptr<KeyFilter> &filter) override;

    QString title() const
    {
        return m_title.isEmpty() && keyFilter() ? keyFilter()->name() : m_title;
    }
    void setTitle(const QString &title);

    QString toolTip() const
    {
        return m_toolTip.isEmpty() ? title() : m_toolTip;
    }
    // not used void setToolTip(const QString &tip);

    bool canBeClosed() const
    {
        return m_canBeClosed;
    }
    bool canBeRenamed() const
    {
        return m_canBeRenamed;
    }
    bool canChangeStringFilter() const
    {
        return m_canChangeStringFilter;
    }
    bool canChangeKeyFilter() const
    {
        return m_canChangeKeyFilter && !m_isTemporary;
    }
    bool canChangeHierarchical() const
    {
        return m_canChangeHierarchical;
    }

    Page *clone() const override
    {
        return new Page(*this);
    }

    void liftAllRestrictions()
    {
        m_canBeClosed = m_canBeRenamed = m_canChangeStringFilter = m_canChangeKeyFilter = m_canChangeHierarchical = true;
    }

    void closePage()
    {
        m_configGroup.deleteGroup();
        m_configGroup.sync();
    }

    KConfigGroup configGroup() const
    {
        return m_configGroup;
    }

Q_SIGNALS:
    void titleChanged(const QString &title);

private:
    void init();

private:
    QString m_title;
    QString m_toolTip;
    bool m_isTemporary : 1;
    bool m_canBeClosed : 1;
    bool m_canBeRenamed : 1;
    bool m_canChangeStringFilter : 1;
    bool m_canChangeKeyFilter : 1;
    bool m_canChangeHierarchical : 1;
    KConfigGroup m_configGroup;
};
} // anon namespace

Page::Page(const Page &other)
    : KeyTreeView(other)
    , m_title(other.m_title)
    , m_toolTip(other.m_toolTip)
    , m_isTemporary(other.m_isTemporary)
    , m_canBeClosed(other.m_canBeClosed)
    , m_canBeRenamed(other.m_canBeRenamed)
    , m_canChangeStringFilter(other.m_canChangeStringFilter)
    , m_canChangeKeyFilter(other.m_canChangeKeyFilter)
    , m_canChangeHierarchical(other.m_canChangeHierarchical)
    , m_configGroup(other.configGroup().config()->group(QUuid::createUuid().toString()))
{
    init();
}

Page::Page(const QString &title,
           const QString &id,
           const QString &text,
           AbstractKeyListSortFilterProxyModel *proxy,
           const QString &toolTip,
           QWidget *parent,
           const KConfigGroup &group,
           KeyTreeView::Options options)
    : KeyTreeView(text, KeyFilterManager::instance()->keyFilterByID(id), proxy, parent, group, options)
    , m_title(title)
    , m_toolTip(toolTip)
    , m_isTemporary(false)
    , m_canBeClosed(true)
    , m_canBeRenamed(true)
    , m_canChangeStringFilter(true)
    , m_canChangeKeyFilter(true)
    , m_canChangeHierarchical(true)
    , m_configGroup(group)
{
    init();
}

static const char TITLE_ENTRY[] = "title";
static const char STRING_FILTER_ENTRY[] = "string-filter";
static const char KEY_FILTER_ENTRY[] = "key-filter";
static const char HIERARCHICAL_VIEW_ENTRY[] = "hierarchical-view";
static const char COLUMN_SIZES[] = "column-sizes";
static const char SORT_COLUMN[] = "sort-column";
static const char SORT_DESCENDING[] = "sort-descending";

Page::Page(const KConfigGroup &group, KeyTreeView::Options options, QWidget *parent)
    : KeyTreeView(group.readEntry(STRING_FILTER_ENTRY),
                  KeyFilterManager::instance()->keyFilterByID(group.readEntry(KEY_FILTER_ENTRY)),
                  nullptr,
                  parent,
                  group,
                  options)
    , m_title(group.readEntry(TITLE_ENTRY))
    , m_toolTip()
    , m_isTemporary(false)
    , m_canBeClosed(!group.isImmutable())
    , m_canBeRenamed(!group.isEntryImmutable(TITLE_ENTRY))
    , m_canChangeStringFilter(!group.isEntryImmutable(STRING_FILTER_ENTRY))
    , m_canChangeKeyFilter(!group.isEntryImmutable(KEY_FILTER_ENTRY))
    , m_canChangeHierarchical(!group.isEntryImmutable(HIERARCHICAL_VIEW_ENTRY))
    , m_configGroup(group)
{
    init();
    setHierarchicalView(group.readEntry(HIERARCHICAL_VIEW_ENTRY, true));
    const QList<int> settings = group.readEntry(COLUMN_SIZES, QList<int>());
    std::vector<int> sizes;
    sizes.reserve(settings.size());
    std::copy(settings.cbegin(), settings.cend(), std::back_inserter(sizes));
    setColumnSizes(sizes);
    setSortColumn(group.readEntry(SORT_COLUMN, 0), group.readEntry(SORT_DESCENDING, true) ? Qt::DescendingOrder : Qt::AscendingOrder);
}

void Page::init()
{
// check for GpgME >= 1.24.0
#if GPGME_VERSION_NUMBER >= 0x011800 && !defined(Q_OS_WIN)
    view()->setDragDropMode(QAbstractItemView::DragOnly);
    view()->setDragEnabled(true);
#endif
}

Page::~Page()
{
}

void Page::setStringFilter(const QString &filter)
{
    if (!m_canChangeStringFilter) {
        return;
    }
    KeyTreeView::setStringFilter(filter);
    m_configGroup.writeEntry(STRING_FILTER_ENTRY, stringFilter());
    m_configGroup.sync();
}

void Page::setKeyFilter(const std::shared_ptr<KeyFilter> &filter)
{
    if (!canChangeKeyFilter()) {
        return;
    }
    const QString oldTitle = title();
    KeyTreeView::setKeyFilter(filter);
    const QString newTitle = title();
    if (oldTitle != newTitle) {
        Q_EMIT titleChanged(newTitle);
    }
    m_configGroup.writeEntry(KEY_FILTER_ENTRY, keyFilter() ? keyFilter()->id() : QString());
    m_configGroup.sync();
}

void Page::setTitle(const QString &t)
{
    if (t == m_title) {
        return;
    }
    if (!m_canBeRenamed) {
        return;
    }
    const QString oldTitle = title();
    m_title = t;
    const QString newTitle = title();
    if (oldTitle != newTitle) {
        Q_EMIT titleChanged(newTitle);
        m_configGroup.writeEntry(TITLE_ENTRY, m_title);
        m_configGroup.sync();
    }
}

#if 0 // not used
void Page::setToolTip(const QString &tip)
{
    if (tip == m_toolTip) {
        return;
    }
    if (!m_canBeRenamed) {
        return;
    }
    const QString oldTip = toolTip();
    m_toolTip = tip;
    const QString newTip = toolTip();
    if (oldTip != newTip) {
        Q_EMIT titleChanged(title());
    }
}
#endif

void Page::setHierarchicalView(bool on)
{
    if (!m_canChangeHierarchical) {
        return;
    }
    KeyTreeView::setHierarchicalView(on);
    m_configGroup.writeEntry(HIERARCHICAL_VIEW_ENTRY, on);
    m_configGroup.sync();
}

void Page::setTemporary(bool on)
{
    if (on == m_isTemporary) {
        return;
    }
    m_isTemporary = on;
    if (on) {
        setKeyFilter(std::shared_ptr<KeyFilter>());
    }
}

namespace
{
class Actions
{
public:
    constexpr static const char *Rename = "window_rename_tab";
    constexpr static const char *Duplicate = "window_duplicate_tab";
    constexpr static const char *Close = "window_close_tab";
    constexpr static const char *MoveLeft = "window_move_tab_left";
    constexpr static const char *MoveRight = "window_move_tab_right";
    constexpr static const char *Hierarchical = "window_view_hierarchical";
    constexpr static const char *ExpandAll = "window_expand_all";
    constexpr static const char *CollapseAll = "window_collapse_all";

    explicit Actions()
    {
    }

    void insert(const std::string &name, QAction *action)
    {
        actions.insert({name, action});
    }

    auto get(const std::string &name) const
    {
        const auto it = actions.find(name);
        return (it != actions.end()) ? it->second : nullptr;
    }

    void setChecked(const std::string &name, bool checked) const
    {
        if (auto action = get(name)) {
            action->setChecked(checked);
        }
    }

    void setEnabled(const std::string &name, bool enabled) const
    {
        if (auto action = get(name)) {
            action->setEnabled(enabled);
        }
    }

    void setVisible(const std::string &name, bool visible) const
    {
        if (auto action = get(name)) {
            action->setVisible(visible);
        }
    }

private:
    std::map<std::string, QAction *> actions;
};
}

//
//
// TabWidget
//
//

class TabWidget::Private
{
    friend class ::Kleo::TabWidget;
    TabWidget *const q;

public:
    explicit Private(TabWidget *qq, KeyTreeView::Options options);
    ~Private()
    {
    }

private:
    void slotContextMenu(const QPoint &p);
    void currentIndexChanged(int index);
    void slotPageTitleChanged(const QString &title);
    void slotPageKeyFilterChanged(const std::shared_ptr<KeyFilter> &filter);
    void slotPageStringFilterChanged(const QString &filter);
    void slotPageHierarchyChanged(bool on);

#ifndef QT_NO_INPUTDIALOG
    void slotRenameCurrentTab()
    {
        renamePage(currentPage());
    }
#endif // QT_NO_INPUTDIALOG
    void slotNewTab();
    void slotDuplicateCurrentTab()
    {
        duplicatePage(currentPage());
    }
    void slotCloseCurrentTab()
    {
        closePage(currentPage());
    }
    void slotMoveCurrentTabLeft()
    {
        movePageLeft(currentPage());
    }
    void slotMoveCurrentTabRight()
    {
        movePageRight(currentPage());
    }
    void slotToggleHierarchicalView(bool on)
    {
        toggleHierarchicalView(currentPage(), on);
    }
    void slotExpandAll()
    {
        expandAll(currentPage());
    }
    void slotCollapseAll()
    {
        collapseAll(currentPage());
    }

#ifndef QT_NO_INPUTDIALOG
    void renamePage(Page *page);
#endif
    void duplicatePage(Page *page);
    void closePage(Page *page);
    void movePageLeft(Page *page);
    void movePageRight(Page *page);
    void toggleHierarchicalView(Page *page, bool on);
    void expandAll(Page *page);
    void collapseAll(Page *page);

    void enableDisableCurrentPageActions();
    void enableDisablePageActions(const Actions &actions, const Page *page);

    Page *currentPage() const
    {
        Q_ASSERT(!tabWidget->currentWidget() || qobject_cast<Page *>(tabWidget->currentWidget()));
        return static_cast<Page *>(tabWidget->currentWidget());
    }
    Page *page(unsigned int idx) const
    {
        Q_ASSERT(!tabWidget->widget(idx) || qobject_cast<Page *>(tabWidget->widget(idx)));
        return static_cast<Page *>(tabWidget->widget(idx));
    }

    Page *senderPage() const
    {
        QObject *const sender = q->sender();
        Q_ASSERT(!sender || qobject_cast<Page *>(sender));
        return static_cast<Page *>(sender);
    }

    bool isSenderCurrentPage() const
    {
        Page *const sp = senderPage();
        return sp && sp == currentPage();
    }

    QTreeView *addView(Page *page, Page *columnReference);

private:
    AbstractKeyListModel *flatModel = nullptr;
    AbstractKeyListModel *hierarchicalModel = nullptr;
    QToolButton *newTabButton = nullptr;
    QToolButton *closeTabButton = nullptr;
    QTabWidget *tabWidget = nullptr;
    QAction *newAction = nullptr;
    Actions currentPageActions;
    Actions otherPageActions;
    bool actionsCreated = false;
    KSharedConfig::Ptr config;
    QString configKey;
    KeyTreeView::Options keyTreeViewOptions;
};

TabWidget::Private::Private(TabWidget *qq, KeyTreeView::Options options)
    : q{qq}
    , keyTreeViewOptions(options)
{
    auto layout = new QVBoxLayout{q};
    layout->setContentsMargins(0, 0, 0, 0);

    // create "New Tab" button before tab widget to ensure correct tab order
    newTabButton = new QToolButton{q};

    tabWidget = new QTabWidget{q};
    Q_SET_OBJECT_NAME(tabWidget);

    layout->addWidget(tabWidget);

    tabWidget->setMovable(true);

    tabWidget->tabBar()->setContextMenuPolicy(Qt::CustomContextMenu);

    // create "Close Tab" button after tab widget to ensure correct tab order
    closeTabButton = new QToolButton{q};

    connect(tabWidget, &QTabWidget::currentChanged, q, [this](int index) {
        currentIndexChanged(index);
    });
    connect(tabWidget->tabBar(), &QWidget::customContextMenuRequested, q, [this](const QPoint &p) {
        slotContextMenu(p);
    });
    connect(tabWidget->tabBar(), &QTabBar::tabMoved, q, [this]() {
        q->saveViews();
    });
}

void TabWidget::Private::slotContextMenu(const QPoint &p)
{
    const int tabUnderPos = tabWidget->tabBar()->tabAt(p);
    Page *const contextMenuPage = static_cast<Page *>(tabWidget->widget(tabUnderPos));
    const Page *const current = currentPage();

    const auto actions = contextMenuPage == current ? currentPageActions : otherPageActions;

    enableDisablePageActions(actions, contextMenuPage);

    QMenu menu;
    if (auto action = actions.get(Actions::Rename)) {
        menu.addAction(action);
    }
    menu.addSeparator();
    menu.addAction(newAction);
    if (auto action = actions.get(Actions::Duplicate)) {
        menu.addAction(action);
    }
    menu.addSeparator();
    if (auto action = actions.get(Actions::MoveLeft)) {
        menu.addAction(action);
    }
    if (auto action = actions.get(Actions::MoveRight)) {
        menu.addAction(action);
    }
    menu.addSeparator();
    if (auto action = actions.get(Actions::Close)) {
        menu.addAction(action);
    }

    const QAction *const action = menu.exec(tabWidget->tabBar()->mapToGlobal(p));
    if (!action) {
        return;
    }

    if (contextMenuPage == current || action == newAction) {
        return; // performed through signal/slot connections...
    }

#ifndef QT_NO_INPUTDIALOG
    if (action == otherPageActions.get(Actions::Rename)) {
        renamePage(contextMenuPage);
    }
#endif // QT_NO_INPUTDIALOG
    else if (action == otherPageActions.get(Actions::Duplicate)) {
        duplicatePage(contextMenuPage);
    } else if (action == otherPageActions.get(Actions::Close)) {
        closePage(contextMenuPage);
    } else if (action == otherPageActions.get(Actions::MoveLeft)) {
        movePageLeft(contextMenuPage);
    } else if (action == otherPageActions.get(Actions::MoveRight)) {
        movePageRight(contextMenuPage);
    }
}

void TabWidget::Private::currentIndexChanged(int index)
{
    const Page *const page = this->page(index);
    Q_EMIT q->currentViewChanged(page ? page->view() : nullptr);
    Q_EMIT q->keyFilterChanged(page ? page->keyFilter() : std::shared_ptr<KeyFilter>());
    Q_EMIT q->stringFilterChanged(page ? page->stringFilter() : QString());
    enableDisableCurrentPageActions();
}

void TabWidget::Private::enableDisableCurrentPageActions()
{
    const Page *const page = currentPage();

    Q_EMIT q->enableChangeStringFilter(page && page->canChangeStringFilter());
    Q_EMIT q->enableChangeKeyFilter(page && page->canChangeKeyFilter());

    enableDisablePageActions(currentPageActions, page);
}

void TabWidget::Private::enableDisablePageActions(const Actions &actions, const Page *p)
{
    actions.setEnabled(Actions::Rename, p && p->canBeRenamed());
    actions.setEnabled(Actions::Duplicate, p);
    actions.setEnabled(Actions::Close, p && p->canBeClosed() && tabWidget->count() > 1);
    actions.setEnabled(Actions::MoveLeft, p && tabWidget->indexOf(const_cast<Page *>(p)) != 0);
    actions.setEnabled(Actions::MoveRight, p && tabWidget->indexOf(const_cast<Page *>(p)) != tabWidget->count() - 1);
    actions.setEnabled(Actions::Hierarchical, p && p->canChangeHierarchical());
    actions.setChecked(Actions::Hierarchical, p && p->isHierarchicalView());
    actions.setVisible(Actions::Hierarchical, Kleo::Settings{}.cmsEnabled());
    actions.setEnabled(Actions::ExpandAll, p && p->isHierarchicalView());
    actions.setEnabled(Actions::CollapseAll, p && p->isHierarchicalView());
}

void TabWidget::Private::slotPageTitleChanged(const QString &)
{
    if (Page *const page = senderPage()) {
        const int idx = tabWidget->indexOf(page);
        tabWidget->setTabText(idx, page->title());
        tabWidget->setTabToolTip(idx, page->toolTip());
    }
}

void TabWidget::Private::slotPageKeyFilterChanged(const std::shared_ptr<KeyFilter> &kf)
{
    if (isSenderCurrentPage()) {
        Q_EMIT q->keyFilterChanged(kf);
    }
}

void TabWidget::Private::slotPageStringFilterChanged(const QString &filter)
{
    if (isSenderCurrentPage()) {
        Q_EMIT q->stringFilterChanged(filter);
    }
}

void TabWidget::Private::slotPageHierarchyChanged(bool)
{
    enableDisableCurrentPageActions();
}

void TabWidget::Private::slotNewTab()
{
    auto group = KSharedConfig::openStateConfig()->group(QStringLiteral("%1:View %2").arg(configKey, QUuid::createUuid().toString()));
    Page *page = new Page(QString(), QStringLiteral("all-certificates"), QString(), nullptr, QString(), nullptr, group, keyTreeViewOptions);
    group.writeEntry(KEY_FILTER_ENTRY, QStringLiteral("all-certificates"));
    group.sync();
    addView(page, currentPage());
    tabWidget->setCurrentIndex(tabWidget->count() - 1);
    q->saveViews();
}

void TabWidget::Private::renamePage(Page *page)
{
    if (!page) {
        return;
    }
    bool ok;
    const QString text = QInputDialog::getText(q, i18n("Rename Tab"), i18n("New tab title:"), QLineEdit::Normal, page->title(), &ok);
    if (!ok) {
        return;
    }
    page->setTitle(text);
}

void TabWidget::Private::duplicatePage(Page *page)
{
    if (!page) {
        return;
    }
    Page *const clone = page->clone();
    Q_ASSERT(clone);
    clone->liftAllRestrictions();
    addView(clone, page);
}

void TabWidget::Private::closePage(Page *page)
{
    if (!page || !page->canBeClosed() || tabWidget->count() <= 1) {
        return;
    }
    Q_EMIT q->viewAboutToBeRemoved(page->view());
    page->closePage();
    tabWidget->removeTab(tabWidget->indexOf(page));
    q->saveViews();
    enableDisableCurrentPageActions();
}

void TabWidget::Private::movePageLeft(Page *page)
{
    if (!page) {
        return;
    }
    const int idx = tabWidget->indexOf(page);
    if (idx <= 0) {
        return;
    }
    tabWidget->tabBar()->moveTab(idx, idx - 1);
    enableDisableCurrentPageActions();
}

void TabWidget::Private::movePageRight(Page *page)
{
    if (!page) {
        return;
    }
    const int idx = tabWidget->indexOf(page);
    if (idx < 0 || idx >= tabWidget->count() - 1) {
        return;
    }
    tabWidget->tabBar()->moveTab(idx, idx + 1);
    enableDisableCurrentPageActions();
}

void TabWidget::Private::toggleHierarchicalView(Page *page, bool on)
{
    if (!page) {
        return;
    }
    page->setHierarchicalView(on);
}

void TabWidget::Private::expandAll(Page *page)
{
    if (!page || !page->view()) {
        return;
    }
    page->view()->expandAll();
}

void TabWidget::Private::collapseAll(Page *page)
{
    if (!page || !page->view()) {
        return;
    }
    page->view()->collapseAll();
}

TabWidget::TabWidget(KeyTreeView::Options options, QWidget *p, Qt::WindowFlags f)
    : QWidget(p, f)
    , d(new Private(this, options))
{
}

TabWidget::~TabWidget()
{
    saveViews();
}

void TabWidget::setFlatModel(AbstractKeyListModel *model)
{
    if (model == d->flatModel) {
        return;
    }
    d->flatModel = model;
    for (unsigned int i = 0, end = count(); i != end; ++i)
        if (Page *const page = d->page(i)) {
            page->setFlatModel(model);
        }
}

AbstractKeyListModel *TabWidget::flatModel() const
{
    return d->flatModel;
}

void TabWidget::setHierarchicalModel(AbstractKeyListModel *model)
{
    if (model == d->hierarchicalModel) {
        return;
    }
    d->hierarchicalModel = model;
    for (unsigned int i = 0, end = count(); i != end; ++i)
        if (Page *const page = d->page(i)) {
            page->setHierarchicalModel(model);
        }
}

AbstractKeyListModel *TabWidget::hierarchicalModel() const
{
    return d->hierarchicalModel;
}

QString TabWidget::stringFilter() const
{
    return d->currentPage() ? d->currentPage()->stringFilter() : QString{};
}

void TabWidget::setStringFilter(const QString &filter)
{
    if (Page *const page = d->currentPage()) {
        page->setStringFilter(filter);
    }
}

void TabWidget::setKeyFilter(const std::shared_ptr<KeyFilter> &filter)
{
    if (!filter) {
        qCDebug(KLEOPATRA_LOG) << "TabWidget::setKeyFilter() trial to set filter=NULL";
        return;
    }

    if (Page *const page = d->currentPage()) {
        page->setKeyFilter(filter);
    }
}

std::vector<QAbstractItemView *> TabWidget::views() const
{
    std::vector<QAbstractItemView *> result;
    const unsigned int N = count();
    result.reserve(N);
    for (unsigned int i = 0; i != N; ++i)
        if (const Page *const p = d->page(i)) {
            result.push_back(p->view());
        }
    return result;
}

QAbstractItemView *TabWidget::currentView() const
{
    if (Page *const page = d->currentPage()) {
        return page->view();
    } else {
        return nullptr;
    }
}

KeyListModelInterface *TabWidget::currentModel() const
{
    const QAbstractItemView *const view = currentView();
    if (!view) {
        return nullptr;
    }
    auto const proxy = qobject_cast<QAbstractProxyModel *>(view->model());
    if (!proxy) {
        return nullptr;
    }
    return dynamic_cast<KeyListModelInterface *>(proxy);
}

unsigned int TabWidget::count() const
{
    return d->tabWidget->count();
}

void TabWidget::setMultiSelection(bool on)
{
    for (unsigned int i = 0, end = count(); i != end; ++i)
        if (const Page *const p = d->page(i))
            if (QTreeView *const view = p->view()) {
                view->setSelectionMode(on ? QAbstractItemView::ExtendedSelection : QAbstractItemView::SingleSelection);
            }
}

void TabWidget::createActions(KActionCollection *coll)
{
    if (!coll) {
        return;
    }
    const action_data actionDataNew = {
        "window_new_tab",
        i18n("New Tab"),
        i18n("Open a new tab"),
        "tab-new-background",
        this,
        [this](bool) {
            d->slotNewTab();
        },
        QStringLiteral("CTRL+SHIFT+N"),
    };

    d->newAction = make_action_from_data(actionDataNew, coll);

    const std::vector<action_data> actionData = {
        {
            Actions::Rename,
            i18n("Rename Tab..."),
            i18n("Rename this tab"),
            "edit-rename",
            this,
            [this](bool) {
                d->slotRenameCurrentTab();
            },
            QStringLiteral("CTRL+SHIFT+R"),
            RegularQAction,
            Disabled,
        },
        {
            Actions::Duplicate,
            i18n("Duplicate Tab"),
            i18n("Duplicate this tab"),
            "tab-duplicate",
            this,
            [this](bool) {
                d->slotDuplicateCurrentTab();
            },
            QStringLiteral("CTRL+SHIFT+D"),
        },
        {
            Actions::Close,
            i18n("Close Tab"),
            i18n("Close this tab"),
            "tab-close",
            this,
            [this](bool) {
                d->slotCloseCurrentTab();
            },
            QStringLiteral("CTRL+SHIFT+W"),
            RegularQAction,
            Disabled,
        }, // ### CTRL-W when available
        {
            Actions::MoveLeft,
            i18n("Move Tab Left"),
            i18n("Move this tab left"),
            nullptr,
            this,
            [this](bool) {
                d->slotMoveCurrentTabLeft();
            },
            QStringLiteral("CTRL+SHIFT+LEFT"),
            RegularQAction,
            Disabled,
        },
        {
            Actions::MoveRight,
            i18n("Move Tab Right"),
            i18n("Move this tab right"),
            nullptr,
            this,
            [this](bool) {
                d->slotMoveCurrentTabRight();
            },
            QStringLiteral("CTRL+SHIFT+RIGHT"),
            RegularQAction,
            Disabled,
        },
        {
            Actions::Hierarchical,
            i18n("Hierarchical Certificate List"),
            QString(),
            nullptr,
            this,
            [this](bool on) {
                d->slotToggleHierarchicalView(on);
            },
            QString(),
            KFToggleAction,
            Disabled,
        },
        {
            Actions::ExpandAll,
            i18n("Expand All"),
            QString(),
            nullptr,
            this,
            [this](bool) {
                d->slotExpandAll();
            },
            QStringLiteral("CTRL+."),
            RegularQAction,
            Disabled,
        },
        {
            Actions::CollapseAll,
            i18n("Collapse All"),
            QString(),
            nullptr,
            this,
            [this](bool) {
                d->slotCollapseAll();
            },
            QStringLiteral("CTRL+,"),
            RegularQAction,
            Disabled,
        },
    };

    for (const auto &ad : actionData) {
        d->currentPageActions.insert(ad.name, make_action_from_data(ad, coll));
    }

    for (const auto &ad : actionData) {
        // create actions for the context menu of the currently not active tabs,
        // but do not add those actions to the action collection
        auto action = new QAction(ad.text, coll);
        if (ad.icon) {
            action->setIcon(QIcon::fromTheme(QLatin1StringView(ad.icon)));
        }
        action->setEnabled(ad.actionState == Enabled);
        d->otherPageActions.insert(ad.name, action);
    }

    d->newTabButton->setDefaultAction(d->newAction);
    d->tabWidget->setCornerWidget(d->newTabButton, Qt::TopLeftCorner);
    if (auto action = d->currentPageActions.get(Actions::Close)) {
        d->closeTabButton->setDefaultAction(action);
        d->tabWidget->setCornerWidget(d->closeTabButton, Qt::TopRightCorner);
    } else {
        d->closeTabButton->setVisible(false);
    }
    d->actionsCreated = true;
}

QAbstractItemView *TabWidget::addView(const QString &title, const QString &id, const QString &text)
{
    auto group = KSharedConfig::openStateConfig()->group(QStringLiteral("%1:View %2").arg(d->configKey, QUuid::createUuid().toString()));
    Page *page = new Page(title, id, text, nullptr, QString(), nullptr, group, d->keyTreeViewOptions);
    group.writeEntry(KEY_FILTER_ENTRY, id);
    group.sync();
    QMetaObject::invokeMethod(
        this,
        [page, group]() {
            page->restoreLayout(group);
        },
        Qt::QueuedConnection);
    return d->addView(page, d->currentPage());
}

QAbstractItemView *TabWidget::addView(const KConfigGroup &group, Options options)
{
    Page *page = nullptr;
    if (options & ShowUserIDs) {
        page = new Page(group.readEntry(TITLE_ENTRY),
                        group.readEntry(KEY_FILTER_ENTRY),
                        group.readEntry(STRING_FILTER_ENTRY),
                        new UserIDProxyModel(this),
                        {},
                        nullptr,
                        group,
                        d->keyTreeViewOptions);
    } else {
        page = new Page(group, d->keyTreeViewOptions);
    }
    QMetaObject::invokeMethod(
        this,
        [page, group]() {
            page->restoreLayout(group);
        },
        Qt::QueuedConnection);
    return d->addView(page, nullptr);
}

QAbstractItemView *TabWidget::addTemporaryView(const QString &title, AbstractKeyListSortFilterProxyModel *proxy, const QString &tabToolTip)
{
    const KConfigGroup group = KSharedConfig::openConfig()->group(QStringLiteral("KeyTreeView_default"));
    Page *const page = new Page(title, QString(), QString(), proxy, tabToolTip, nullptr, group, d->keyTreeViewOptions);
    page->setTemporary(true);
    QAbstractItemView *v = d->addView(page, d->currentPage());
    d->tabWidget->setCurrentIndex(d->tabWidget->count() - 1);
    return v;
}

QTreeView *TabWidget::Private::addView(Page *page, Page *columnReference)
{
    if (!page) {
        return nullptr;
    }

    if (!actionsCreated) {
        auto coll = new KActionCollection(q);
        q->createActions(coll);
    }

    page->setFlatModel(flatModel);
    page->setHierarchicalModel(hierarchicalModel);

    connect(page, &Page::titleChanged, q, [this](const QString &text) {
        slotPageTitleChanged(text);
    });
    connect(page, &Page::keyFilterChanged, q, [this](const std::shared_ptr<Kleo::KeyFilter> &filter) {
        slotPageKeyFilterChanged(filter);
    });
    connect(page, &Page::stringFilterChanged, q, [this](const QString &text) {
        slotPageStringFilterChanged(text);
    });
    connect(page, &Page::hierarchicalChanged, q, [this](bool on) {
        slotPageHierarchyChanged(on);
    });

    if (columnReference) {
        QMetaObject::invokeMethod(
            q,
            [=]() {
                page->setColumnSizes(columnReference->columnSizes());
                page->setSortColumn(columnReference->sortColumn(), columnReference->sortOrder());
                page->view()->saveColumnLayout(page->configGroup().name());
            },
            Qt::QueuedConnection);
        for (auto i = 0; i < columnReference->view()->model()->columnCount(); i++) {
            page->view()->setColumnHidden(i, columnReference->view()->isColumnHidden(i));
            page->view()->header()->moveSection(page->view()->header()->visualIndex(i), columnReference->view()->header()->visualIndex(i));
        }
        for (auto row = 0; row < page->view()->model()->rowCount(); row++) {
            page->view()->setExpanded(page->view()->model()->index(row, 0),
                                      columnReference->view()->isExpanded(columnReference->view()->model()->index(row, 0)));
        }
    }

    QAbstractItemView *const previous = q->currentView();
    const int tabIndex = tabWidget->addTab(page, page->title());
    setTabOrder(closeTabButton, page->view());
    tabWidget->setTabToolTip(tabIndex, page->toolTip());
    // work around a bug in QTabWidget (tested with 4.3.2) not emitting currentChanged() when the first widget is inserted
    QAbstractItemView *const current = q->currentView();
    if (previous != current) {
        currentIndexChanged(tabWidget->currentIndex());
    }
    enableDisableCurrentPageActions();
    QTreeView *view = page->view();
    Q_EMIT q->viewAdded(view);
    return view;
}

static QStringList extractViewGroups(const KConfigGroup &config)
{
    return config.readEntry("Tabs", QStringList());
}

void TabWidget::loadViews(const KSharedConfig::Ptr &config, const QString &configKey, Options options)
{
    d->config = config;
    d->configKey = configKey;
    QStringList groupList = extractViewGroups(config->group(configKey));
    for (const QString &view : std::as_const(groupList)) {
        addView(KConfigGroup(config, view), options);
    }
    if (!count()) {
        // add default view:
        addView({}, QStringLiteral("all-certificates"));
    }
}

void TabWidget::saveViews()
{
    if (!d->config) {
        return;
    }
    QStringList tabs;
    for (unsigned int i = 0, end = count(); i != end; ++i) {
        if (Page *const p = d->page(i)) {
            if (p->isTemporary()) {
                continue;
            }
            tabs += p->configGroup().name();
        }
    }
    d->config->group(d->configKey).writeEntry("Tabs", tabs);
    d->config->sync();
}

void TabWidget::connectSearchBar(SearchBar *sb)
{
    connect(sb, &SearchBar::stringFilterChanged, this, &TabWidget::setStringFilter);
    connect(this, &TabWidget::stringFilterChanged, sb, &SearchBar::setStringFilter);

    connect(sb, &SearchBar::keyFilterChanged, this, &TabWidget::setKeyFilter);
    connect(this, &TabWidget::keyFilterChanged, sb, &SearchBar::setKeyFilter);

    connect(this, &TabWidget::enableChangeStringFilter, sb, &SearchBar::setChangeStringFilterEnabled);
    connect(this, &TabWidget::enableChangeKeyFilter, sb, &SearchBar::setChangeKeyFilterEnabled);
}

#include "moc_tabwidget.cpp"
#include "tabwidget.moc"
