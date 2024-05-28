/* -*- mode: c++; c-basic-offset:4 -*-
    view/keytreeview.h

    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2009 Klarälvdalens Datakonsult AB

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#pragma once

#include <QWidget>

#include <QString>
#include <QStringList>

#include <gpgme++/key.h>

#include <memory>
#include <vector>

#include <KConfigGroup>

#include <Libkleo/TreeView>

class QTreeView;

namespace Kleo
{

class KeyFilter;
class AbstractKeyListModel;
class AbstractKeyListSortFilterProxyModel;
class KeyListSortFilterProxyModel;
class SearchBar;

class KeyTreeView : public QWidget
{
    Q_OBJECT

    Q_FLAGS(Options)
public:
    enum Option {
        Default = 0x0,
        NoDefaultContextMenu = 0x1,
    };
    Q_DECLARE_FLAGS(Options, Option)

    explicit KeyTreeView(QWidget *parent = nullptr);
    KeyTreeView(const QString &stringFilter,
                const std::shared_ptr<KeyFilter> &keyFilter,
                AbstractKeyListSortFilterProxyModel *additionalProxy,
                QWidget *parent,
                const KConfigGroup &group,
                Options options = Option::Default);
    ~KeyTreeView() override;

    TreeView *view() const
    {
        return m_view;
    }

    AbstractKeyListModel *model() const
    {
        return m_isHierarchical ? hierarchicalModel() : flatModel();
    }

    AbstractKeyListModel *flatModel() const
    {
        return m_flatModel;
    }
    AbstractKeyListModel *hierarchicalModel() const
    {
        return m_hierarchicalModel;
    }

    void setFlatModel(AbstractKeyListModel *model);
    void setHierarchicalModel(AbstractKeyListModel *model);

    // extraOrigins contains additional origin information for the keys. It must be in the same order as the keys themselves.
    // For this reason, setKeys will NOT perform any sorting and filtering if extraOrigins is not empty.
    void setKeys(const std::vector<GpgME::Key> &keys, const std::vector<GpgME::Key::Origin> &extraOrigins = {});
    const std::vector<GpgME::Key> &keys() const
    {
        return m_keys;
    }

    void selectKeys(const std::vector<GpgME::Key> &keys);
    std::vector<GpgME::Key> selectedKeys() const;

    void addKeysUnselected(const std::vector<GpgME::Key> &keys);
    void addKeysSelected(const std::vector<GpgME::Key> &keys);
    void removeKeys(const std::vector<GpgME::Key> &keys);

#if 0
    void setToolTipOptions(int options);
    int toolTipOptions() const;
#endif

    QString stringFilter() const
    {
        return m_stringFilter;
    }
    const std::shared_ptr<KeyFilter> &keyFilter() const
    {
        return m_keyFilter;
    }
    bool isHierarchicalView() const
    {
        return m_isHierarchical;
    }

    void setColumnSizes(const std::vector<int> &sizes);
    std::vector<int> columnSizes() const;

    void setSortColumn(int sortColumn, Qt::SortOrder sortOrder);
    int sortColumn() const;
    Qt::SortOrder sortOrder() const;

    virtual KeyTreeView *clone() const
    {
        return new KeyTreeView(*this);
    }

    void disconnectSearchBar();
    bool connectSearchBar(const SearchBar *bar);
    void restoreLayout(const KConfigGroup &group);

public Q_SLOTS:
    virtual void setStringFilter(const QString &text);
    virtual void setKeyFilter(const std::shared_ptr<Kleo::KeyFilter> &filter);
    virtual void setHierarchicalView(bool on);

Q_SIGNALS:
    void stringFilterChanged(const QString &filter);
    void keyFilterChanged(const std::shared_ptr<Kleo::KeyFilter> &filter);
    void hierarchicalChanged(bool on);

protected:
    KeyTreeView(const KeyTreeView &);
    void keyPressEvent(QKeyEvent *event) override;

private:
    void init();
    void initializeColumnSizes();
    void addKeysImpl(const std::vector<GpgME::Key> &, bool);
    void restoreExpandState();
    void setUpTagKeys();
    void updateModelConnections(AbstractKeyListModel *oldModel, AbstractKeyListModel *newModel);
    void saveStateBeforeModelChange();
    void restoreStateAfterModelChange();

private:
    std::vector<GpgME::Key> m_keys;

    KeyListSortFilterProxyModel *m_proxy;
    AbstractKeyListSortFilterProxyModel *m_additionalProxy;

    TreeView *m_view;

    AbstractKeyListModel *m_flatModel;
    AbstractKeyListModel *m_hierarchicalModel;

    QString m_stringFilter;
    std::shared_ptr<KeyFilter> m_keyFilter;

    QStringList m_expandedKeys;
    std::vector<GpgME::Key> m_selectedKeys;
    GpgME::Key m_currentKey;

    std::vector<QMetaObject::Connection> m_connections;

    KConfigGroup m_group;

    bool m_isHierarchical : 1;
    bool m_onceResized : 1;
    bool m_showDefaultContextMenu : 1;
};

}
