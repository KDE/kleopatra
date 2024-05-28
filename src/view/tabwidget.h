/* -*- mode: c++; c-basic-offset:4 -*-
    view/tabwidget.h

    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2007 Klarälvdalens Datakonsult AB

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#pragma once

#include "keytreeview.h"

#include <KSharedConfig>

#include <QWidget>

#include <memory>
#include <vector>

class QAbstractItemView;

class KConfigGroup;
class KActionCollection;

namespace Kleo
{

class AbstractKeyListModel;
class AbstractKeyListSortFilterProxyModel;
class KeyFilter;
class KeyListModelInterface;
class SearchBar;

class TabWidget : public QWidget
{
    Q_OBJECT
public:
    enum Option {
        ShowKeys = 0x00,
        ShowUserIDs = 0x01,
    };
    Q_DECLARE_FLAGS(Options, Option)

    explicit TabWidget(KeyTreeView::Options options = KeyTreeView::Option::Default, QWidget *parent = nullptr, Qt::WindowFlags f = {});
    ~TabWidget() override;

    void setFlatModel(AbstractKeyListModel *model);
    AbstractKeyListModel *flatModel() const;
    void setHierarchicalModel(AbstractKeyListModel *model);
    AbstractKeyListModel *hierarchicalModel() const;

    QAbstractItemView *addView(const QString &title = QString(), const QString &keyFilterID = QString(), const QString &searchString = QString());
    QAbstractItemView *addView(const KConfigGroup &group, Options options);
    QAbstractItemView *
    addTemporaryView(const QString &title = QString(), AbstractKeyListSortFilterProxyModel *proxy = nullptr, const QString &tabToolTip = QString());

    void loadViews(const KSharedConfig::Ptr &config, const QString &configKeys, Options options = ShowKeys);
    void saveViews();

    std::vector<QAbstractItemView *> views() const;
    QAbstractItemView *currentView() const;
    KeyListModelInterface *currentModel() const;

    unsigned int count() const;

    void createActions(KActionCollection *collection);
    void connectSearchBar(SearchBar *sb);

    void setMultiSelection(bool on);

    QString stringFilter() const;

public Q_SLOTS:
    void setKeyFilter(const std::shared_ptr<Kleo::KeyFilter> &filter);
    void setStringFilter(const QString &filter);

Q_SIGNALS:
    void viewAdded(QAbstractItemView *view);
    void viewAboutToBeRemoved(QAbstractItemView *view);

    void currentViewChanged(QAbstractItemView *view);
    void stringFilterChanged(const QString &filter);
    void keyFilterChanged(const std::shared_ptr<Kleo::KeyFilter> &filter);

    void enableChangeStringFilter(bool enable);
    void enableChangeKeyFilter(bool enable);

private:
    class Private;
    const std::unique_ptr<Private> d;
};

}
