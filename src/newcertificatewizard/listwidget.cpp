/*
    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2008 Klarälvdalens Datakonsult AB

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include <config-kleopatra.h>

#include "listwidget.h"

#include "ui_listwidget.h"

#include <QIcon>

#include <QItemDelegate>
#include <QLineEdit>
#include <QRegularExpressionValidator>
#include <QStringListModel>

using namespace Kleo::NewCertificateUi;

namespace
{

class ItemDelegate : public QItemDelegate
{
    Q_OBJECT
public:
    explicit ItemDelegate(QObject *p = nullptr)
        : QItemDelegate(p)
        , m_rx()
    {
    }
    explicit ItemDelegate(const QRegularExpression &rx, QObject *p = nullptr)
        : QItemDelegate(p)
        , m_rx(rx)
    {
    }

    void setRegExpFilter(const QRegularExpression &rx)
    {
        m_rx = rx;
    }
    const QRegularExpression &regExpFilter() const
    {
        return m_rx;
    }

    QWidget *createEditor(QWidget *p, const QStyleOptionViewItem &o, const QModelIndex &i) const override
    {
        QWidget *w = QItemDelegate::createEditor(p, o, i);
        if (m_rx.isValid())
            if (auto const le = qobject_cast<QLineEdit *>(w)) {
                le->setValidator(new QRegularExpressionValidator(m_rx, le));
            }
        return w;
    }

private:
    QRegularExpression m_rx;
};
}

class ListWidget::Private
{
    friend class ::Kleo::NewCertificateUi::ListWidget;
    ListWidget *const q;

public:
    explicit Private(ListWidget *qq)
        : q(qq)
        , stringListModel()
        , ui(q)
    {
        ui.listView->setModel(&stringListModel);
        ui.listView->setItemDelegate(&delegate);
        connect(ui.listView->selectionModel(), SIGNAL(selectionChanged(QItemSelection, QItemSelection)), q, SLOT(slotSelectionChanged()));
        connect(&stringListModel, &QAbstractItemModel::dataChanged, q, &ListWidget::itemsChanged);
        connect(&stringListModel, &QAbstractItemModel::rowsInserted, q, &ListWidget::itemsChanged);
        connect(&stringListModel, &QAbstractItemModel::rowsRemoved, q, &ListWidget::itemsChanged);
    }

private:
    void slotAdd()
    {
        const int idx = stringListModel.rowCount();
        if (stringListModel.insertRows(idx, 1)) {
            stringListModel.setData(stringListModel.index(idx), defaultValue);
            editRow(idx);
        }
    }

    void slotRemove()
    {
        const int idx = selectedRow();
        stringListModel.removeRows(idx, 1);
        selectRow(idx);
    }

    void slotUp()
    {
        const int idx = selectedRow();
        swapRows(idx - 1, idx);
        selectRow(idx - 1);
    }

    void slotDown()
    {
        const int idx = selectedRow();
        swapRows(idx, idx + 1);
        selectRow(idx + 1);
    }

    void slotSelectionChanged()
    {
        enableDisableActions();
    }

private:
    void editRow(int idx)
    {
        const QModelIndex mi = stringListModel.index(idx);
        if (!mi.isValid()) {
            return;
        }
        ui.listView->setCurrentIndex(mi);
        ui.listView->edit(mi);
    }

    QModelIndexList selectedIndexes() const
    {
        return ui.listView->selectionModel()->selectedRows();
    }
    int selectedRow() const
    {
        const QModelIndexList mil = selectedIndexes();
        return mil.empty() ? -1 : mil.front().row();
    }
    void selectRow(int idx)
    {
        const QModelIndex mi = stringListModel.index(idx);
        if (mi.isValid()) {
            ui.listView->setCurrentIndex(mi);
        }
    }
    void swapRows(int r1, int r2)
    {
        if (r1 < 0 || r2 < 0 || r1 >= stringListModel.rowCount() || r2 >= stringListModel.rowCount()) {
            return;
        }
        const QModelIndex m1 = stringListModel.index(r1);
        const QModelIndex m2 = stringListModel.index(r2);
        const QVariant data1 = m1.data();
        const QVariant data2 = m2.data();
        stringListModel.setData(m1, data2);
        stringListModel.setData(m2, data1);
    }
    void enableDisableActions()
    {
        const QModelIndexList mil = selectedIndexes();
        ui.removeTB->setEnabled(!mil.empty());
        ui.upTB->setEnabled(mil.size() == 1 && mil.front().row() > 0);
        ui.downTB->setEnabled(mil.size() == 1 && mil.back().row() < stringListModel.rowCount() - 1);
    }

private:
    QStringListModel stringListModel;
    ItemDelegate delegate;
    QString defaultValue;
    struct UI : Ui_ListWidget {
        explicit UI(ListWidget *q)
            : Ui_ListWidget()
        {
            setupUi(q);

            addTB->setIcon(QIcon::fromTheme(QStringLiteral("list-add")));
            addTB->setAccessibleName(i18nc("@action:button", "Add Entry"));
            removeTB->setIcon(QIcon::fromTheme(QStringLiteral("list-remove")));
            removeTB->setAccessibleName(i18nc("@action:button", "Remove Entry"));
            upTB->setIcon(QIcon::fromTheme(QStringLiteral("go-up")));
            upTB->setAccessibleName(i18nc("@action:button", "Move Up"));
            downTB->setIcon(QIcon::fromTheme(QStringLiteral("go-down")));
            downTB->setAccessibleName(i18nc("@action:button", "Move Down"));
        }
    } ui;
};

ListWidget::ListWidget(QWidget *p)
    : QWidget(p)
    , d(new Private(this))
{
}

ListWidget::~ListWidget()
{
}

QStringList ListWidget::items() const
{
    return d->stringListModel.stringList();
}

void ListWidget::setItems(const QStringList &items)
{
    d->stringListModel.setStringList(items);
}

QRegularExpression ListWidget::regExpFilter() const
{
    return d->delegate.regExpFilter();
}

void ListWidget::setRegExpFilter(const QRegularExpression &rx)
{
    d->delegate.setRegExpFilter(rx);
}

QString ListWidget::defaultValue() const
{
    return d->defaultValue;
}

void ListWidget::setDefaultValue(const QString &df)
{
    d->defaultValue = df;
}

#include "listwidget.moc"
#include "moc_listwidget.cpp"
