/* -*- mode: c++; c-basic-offset:4 -*-
    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2007 Klarälvdalens Datakonsult AB

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include <config-kleopatra.h>

#include "objectspage.h"

#include <utils/filedialog.h>

#include <KLocalizedString>
#include <QIcon>

#include <QFileInfo>
#include <QHBoxLayout>
#include <QListWidget>
#include <QPushButton>
#include <QVBoxLayout>

using namespace Kleo;
using namespace Kleo::Crypto::Gui;

class ObjectsPage::Private
{
    friend class ::Kleo::Crypto::Gui::ObjectsPage;
    ObjectsPage *const q;

public:
    explicit Private(ObjectsPage *qq);
    ~Private();
    void add();
    void addFile(const QFileInfo &i);
    void remove();
    void listSelectionChanged();
    enum Role {
        AbsoluteFilePathRole = Qt::UserRole,
    };

private:
    QListWidget *fileListWidget;
    QPushButton *removeButton;
};

ObjectsPage::Private::Private(ObjectsPage *qq)
    : q(qq)
{
    q->setTitle(i18n("<b>Objects</b>"));
    auto const top = new QVBoxLayout(q);
    fileListWidget = new QListWidget;
    fileListWidget->setSelectionMode(QAbstractItemView::MultiSelection);
    connect(fileListWidget, SIGNAL(itemSelectionChanged()), q, SLOT(listSelectionChanged()));
    top->addWidget(fileListWidget);
    auto const buttonWidget = new QWidget;
    auto const buttonLayout = new QHBoxLayout(buttonWidget);
    removeButton = new QPushButton;
    removeButton->setText(i18n("Remove Selected"));
    connect(removeButton, SIGNAL(clicked()), q, SLOT(remove()));
    buttonLayout->addWidget(removeButton);
    buttonLayout->addStretch();
    top->addWidget(buttonWidget);
    listSelectionChanged();
}

ObjectsPage::Private::~Private()
{
}

void ObjectsPage::Private::add()
{
    const QString fname = FileDialog::getOpenFileName(q, i18n("Select File"), QStringLiteral("enc"));
    if (fname.isEmpty()) {
        return;
    }
    addFile(QFileInfo(fname));
    Q_EMIT q->completeChanged();
}

void ObjectsPage::Private::remove()
{
    const QList<QListWidgetItem *> selected = fileListWidget->selectedItems();
    Q_ASSERT(!selected.isEmpty());
    for (QListWidgetItem *const i : selected) {
        delete i;
    }
    Q_EMIT q->completeChanged();
}

void ObjectsPage::Private::listSelectionChanged()
{
    removeButton->setEnabled(!fileListWidget->selectedItems().isEmpty());
}

ObjectsPage::ObjectsPage(QWidget *parent, Qt::WindowFlags f)
    : WizardPage(parent, f)
    , d(new Private(this))
{
}

ObjectsPage::~ObjectsPage()
{
}

void ObjectsPage::setFiles(const QStringList &list)
{
    d->fileListWidget->clear();
    for (const QString &i : list) {
        d->addFile(QFileInfo(i));
    }
    Q_EMIT completeChanged();
}

void ObjectsPage::Private::addFile(const QFileInfo &info)
{
    auto const item = new QListWidgetItem;
    if (info.isDir()) {
        item->setIcon(QIcon::fromTheme(QStringLiteral("folder")));
    }
    item->setText(info.fileName());
    item->setData(AbsoluteFilePathRole, info.absoluteFilePath());
    fileListWidget->addItem(item);
}

QStringList ObjectsPage::files() const
{
    QStringList list;
    for (int i = 0; i < d->fileListWidget->count(); ++i) {
        const QListWidgetItem *const item = d->fileListWidget->item(i);
        list.push_back(item->data(Private::AbsoluteFilePathRole).toString());
    }
    return list;
}

bool ObjectsPage::isComplete() const
{
    return d->fileListWidget->count() > 0;
}

#include "moc_objectspage.cpp"
