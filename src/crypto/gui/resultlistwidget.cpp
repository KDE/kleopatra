/* -*- mode: c++; c-basic-offset:4 -*-
    crypto/gui/resultlistwidget.cpp

    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2008 Klarälvdalens Datakonsult AB

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include <config-kleopatra.h>

#include "resultlistwidget.h"

#include "emailoperationspreferences.h"

#include <crypto/decryptverifytask.h>
#include <crypto/gui/resultitemwidget.h>

#include <utils/gui-helper.h>

#include <Libkleo/Stl_Util>

#include <KAdjustingScrollArea>
#include <KGuiItem>
#include <KLocalizedString>
#include <KStandardGuiItem>

#include <QLabel>
#include <QPushButton>
#include <QVBoxLayout>

using namespace Kleo;
using namespace Kleo::Crypto;
using namespace Kleo::Crypto::Gui;

class ResultListWidget::Private
{
    ResultListWidget *const q;

public:
    explicit Private(ResultListWidget *qq);

    void result(const std::shared_ptr<const Task::Result> &result);
    void started(const std::shared_ptr<Task> &task);
    void allTasksDone();

    void addResultWidget(ResultItemWidget *widget);
    void resizeIfStandalone();

    std::vector<std::shared_ptr<TaskCollection>> m_collections;
    bool m_standaloneMode = false;
    int m_lastErrorItemIndex = 0;
    KAdjustingScrollArea *m_scrollArea = nullptr;
    QPushButton *m_closeButton = nullptr;
    QVBoxLayout *m_layout = nullptr;
    QLabel *m_progressLabel = nullptr;
};

ResultListWidget::Private::Private(ResultListWidget *qq)
    : q(qq)
    , m_collections()
{
    m_layout = new QVBoxLayout(q);
    m_layout->setContentsMargins(0, 0, 0, 0);
    m_layout->setSpacing(0);

    m_scrollArea = new KAdjustingScrollArea;
    m_scrollArea->setFocusPolicy(Qt::NoFocus);
    auto widget = new QWidget;
    m_scrollArea->setWidget(widget);
    auto scrollAreaLayout = new QVBoxLayout(widget);
    scrollAreaLayout->setContentsMargins(0, 0, 0, 0);
    scrollAreaLayout->setSpacing(2);
    scrollAreaLayout->addStretch();
    m_layout->addWidget(m_scrollArea);

    m_progressLabel = new QLabel;
    m_progressLabel->setWordWrap(true);
    m_layout->addWidget(m_progressLabel);
    m_progressLabel->setVisible(false);

    m_closeButton = new QPushButton;
    KGuiItem::assign(m_closeButton, KStandardGuiItem::close());
    q->connect(m_closeButton, &QPushButton::clicked, q, &ResultListWidget::close);
    m_layout->addWidget(m_closeButton);
    m_closeButton->setVisible(false);
    m_closeButton->setEnabled(false);
}

ResultListWidget::ResultListWidget(QWidget *parent, Qt::WindowFlags f)
    : QWidget(parent, f)
    , d(new Private(this))
{
}

ResultListWidget::~ResultListWidget()
{
    if (!d->m_standaloneMode) {
        return;
    }
    EMailOperationsPreferences prefs;
    prefs.setDecryptVerifyPopupGeometry(geometry());
    prefs.save();
}

void ResultListWidget::Private::resizeIfStandalone()
{
    if (m_standaloneMode) {
        q->resize(q->size().expandedTo(q->sizeHint()));
    }
}

void ResultListWidget::Private::addResultWidget(ResultItemWidget *widget)
{
    Q_ASSERT(widget);
    Q_ASSERT(std::any_of(m_collections.cbegin(), m_collections.cend(), [](const std::shared_ptr<TaskCollection> &t) {
        return !t->isEmpty();
    }));

    Q_ASSERT(m_scrollArea);
    Q_ASSERT(m_scrollArea->widget());
    auto scrollAreaLayout = qobject_cast<QBoxLayout *>(m_scrollArea->widget()->layout());
    Q_ASSERT(scrollAreaLayout);
    // insert new widget after last widget showing error or before the trailing stretch
    const auto insertIndex = widget->hasErrorResult() ? m_lastErrorItemIndex++ : scrollAreaLayout->count() - 1;
    scrollAreaLayout->insertWidget(insertIndex, widget);
    if (insertIndex == 0) {
        forceSetTabOrder(m_scrollArea->widget(), widget);
    } else {
        auto previousResultWidget = qobject_cast<ResultItemWidget *>(scrollAreaLayout->itemAt(insertIndex - 1)->widget());
        QWidget::setTabOrder(previousResultWidget, widget);
    }

    widget->show();
    resizeIfStandalone();
}

void ResultListWidget::Private::allTasksDone()
{
    if (!q->isComplete()) {
        return;
    }
    m_progressLabel->setVisible(false);
    resizeIfStandalone();
    Q_EMIT q->completeChanged();
}

void ResultListWidget::Private::result(const std::shared_ptr<const Task::Result> &result)
{
    Q_ASSERT(result);
    Q_ASSERT(std::any_of(m_collections.cbegin(), m_collections.cend(), [](const std::shared_ptr<TaskCollection> &t) {
        return !t->isEmpty();
    }));
    auto wid = new ResultItemWidget(result);
    q->connect(wid, &ResultItemWidget::linkActivated, q, &ResultListWidget::linkActivated);
    q->connect(wid, &ResultItemWidget::closeButtonClicked, q, &ResultListWidget::close);

    const auto viewableContentType = result->viewableContentType();

    if (viewableContentType == Task::Result::ContentType::Mime || viewableContentType == Task::Result::ContentType::Mbox) {
        wid->setShowButton(i18nc("@action:button", "Show Email"), true);
        q->connect(wid, &ResultItemWidget::showButtonClicked, q, [this, result] {
            Q_EMIT q->showButtonClicked(result);
        });
    }

    addResultWidget(wid);
}

bool ResultListWidget::isComplete() const
{
    return std::all_of(d->m_collections.cbegin(), d->m_collections.cend(), std::mem_fn(&TaskCollection::allTasksCompleted));
}

unsigned int ResultListWidget::totalNumberOfTasks() const
{
    return kdtools::accumulate_transform(d->m_collections.cbegin(), d->m_collections.cend(), std::mem_fn(&TaskCollection::size), 0U);
}

unsigned int ResultListWidget::numberOfCompletedTasks() const
{
    return kdtools::accumulate_transform(d->m_collections.cbegin(), d->m_collections.cend(), std::mem_fn(&TaskCollection::numberOfCompletedTasks), 0U);
}

void ResultListWidget::setTaskCollection(const std::shared_ptr<TaskCollection> &coll)
{
    // clear(); ### PENDING(marc) implement
    addTaskCollection(coll);
}

void ResultListWidget::addTaskCollection(const std::shared_ptr<TaskCollection> &coll)
{
    Q_ASSERT(coll);
    Q_ASSERT(!coll->isEmpty());
    d->m_collections.push_back(coll);
    connect(coll.get(),
            SIGNAL(result(std::shared_ptr<const Kleo::Crypto::Task::Result>)),
            this,
            SLOT(result(std::shared_ptr<const Kleo::Crypto::Task::Result>)));
    connect(coll.get(), SIGNAL(started(std::shared_ptr<Kleo::Crypto::Task>)), this, SLOT(started(std::shared_ptr<Kleo::Crypto::Task>)));
    connect(coll.get(), SIGNAL(done()), this, SLOT(allTasksDone()));
    setStandaloneMode(d->m_standaloneMode);
}

void ResultListWidget::Private::started(const std::shared_ptr<Task> &task)
{
    Q_ASSERT(task);
    Q_ASSERT(m_progressLabel);
    m_progressLabel->setText(i18nc("number, operation description", "Operation %1: %2", q->numberOfCompletedTasks() + 1, task->label()));
    resizeIfStandalone();
}

void ResultListWidget::setStandaloneMode(bool standalone)
{
    d->m_standaloneMode = standalone;
    if (totalNumberOfTasks() == 0) {
        return;
    }
    d->m_closeButton->setVisible(standalone);
    d->m_closeButton->setEnabled(standalone);
    d->m_progressLabel->setVisible(standalone);
}

#include "moc_resultlistwidget.cpp"
