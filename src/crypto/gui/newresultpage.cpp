/* -*- mode: c++; c-basic-offset:4 -*-
    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2008 Klarälvdalens Datakonsult AB

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include <config-kleopatra.h>

#include "newresultpage.h"

#include "resultitemwidget.h"
#include "resultlistwidget.h"

#include <crypto/taskcollection.h>

#include <Libkleo/Stl_Util>

#include <KLocalizedString>

#include <QCheckBox>
#include <QHash>
#include <QLabel>
#include <QProgressBar>
#include <QTimer>
#include <QVBoxLayout>

static const int ProgressBarHideDelay = 2000; // 2 secs

using namespace Kleo;
using namespace Kleo::Crypto;
using namespace Kleo::Crypto::Gui;

class NewResultPage::Private
{
    NewResultPage *const q;

public:
    explicit Private(NewResultPage *qq);

    void progress(int progress, int total);
    void result(const std::shared_ptr<const Task::Result> &result);
    void started(const std::shared_ptr<Task> &result);
    void allDone();
    QLabel *labelForTag(const QString &tag);

    std::vector<std::shared_ptr<TaskCollection>> m_collections;
    QTimer m_hideProgressTimer;
    QProgressBar *m_progressBar;
    QHash<QString, QLabel *> m_progressLabelByTag;
    QVBoxLayout *m_progressLabelLayout;
    int m_lastErrorItemIndex;
    ResultListWidget *m_resultList;
};

NewResultPage::Private::Private(NewResultPage *qq)
    : q(qq)
    , m_lastErrorItemIndex(0)
{
    m_hideProgressTimer.setInterval(ProgressBarHideDelay);
    m_hideProgressTimer.setSingleShot(true);

    QBoxLayout *const layout = new QVBoxLayout(q);
    auto const labels = new QWidget;
    m_progressLabelLayout = new QVBoxLayout(labels);
    layout->addWidget(labels);
    m_progressBar = new QProgressBar;
    layout->addWidget(m_progressBar);
    m_resultList = new ResultListWidget;
    connect(m_resultList, &ResultListWidget::linkActivated, q, &NewResultPage::linkActivated);
    layout->addWidget(m_resultList, 1);

    connect(&m_hideProgressTimer, &QTimer::timeout, m_progressBar, &QProgressBar::hide);
}

void NewResultPage::Private::progress(int progress, int total)
{
    Q_ASSERT(progress >= 0);
    Q_ASSERT(total >= 0);
    m_progressBar->setRange(0, total);
    m_progressBar->setValue(progress);
}

void NewResultPage::Private::allDone()
{
    Q_ASSERT(!m_collections.empty());
    if (!m_resultList->isComplete()) {
        return;
    }
    m_progressBar->setRange(0, 100);
    m_progressBar->setValue(100);
    m_collections.clear();
    const auto progressLabelByTagKeys{m_progressLabelByTag.keys()};
    for (const QString &i : progressLabelByTagKeys) {
        if (!i.isEmpty()) {
            m_progressLabelByTag.value(i)->setText(i18n("%1: All operations completed.", i));
        } else {
            m_progressLabelByTag.value(i)->setText(i18n("All operations completed."));
        }
    }
    if (QAbstractButton *cancel = q->wizard()->button(QWizard::CancelButton)) {
        cancel->setEnabled(false);
    }
    Q_EMIT q->completeChanged();
    m_hideProgressTimer.start();
}

void NewResultPage::Private::result(const std::shared_ptr<const Task::Result> &)
{
}

void NewResultPage::Private::started(const std::shared_ptr<Task> &task)
{
    Q_ASSERT(task);
    const QString tag = task->tag();
    QLabel *const label = labelForTag(tag);
    Q_ASSERT(label);
    if (tag.isEmpty()) {
        label->setText(i18nc("number, operation description", "Operation %1: %2", m_resultList->numberOfCompletedTasks() + 1, task->label()));
    } else {
        label->setText(i18nc(R"(tag( "OpenPGP" or "CMS"),  operation description)", "%1: %2", tag, task->label()));
    }
}

NewResultPage::NewResultPage(QWidget *parent)
    : QWizardPage(parent)
    , d(new Private(this))
{
    setTitle(i18n("<b>Results</b>"));
}

NewResultPage::~NewResultPage()
{
}

void NewResultPage::setTaskCollection(const std::shared_ptr<TaskCollection> &coll)
{
    // clear(); ### PENDING(marc) implement
    addTaskCollection(coll);
}

void NewResultPage::addTaskCollection(const std::shared_ptr<TaskCollection> &coll)
{
    Q_ASSERT(coll);
    if (std::find(d->m_collections.cbegin(), d->m_collections.cend(), coll) != d->m_collections.cend()) {
        return;
    }
    d->m_hideProgressTimer.stop();
    d->m_progressBar->show();
    d->m_collections.push_back(coll);
    d->m_resultList->addTaskCollection(coll);
    connect(coll.get(), &TaskCollection::progress, this, [this](int current, int total) {
        d->progress(current, total);
    });
    connect(coll.get(), SIGNAL(done()), this, SLOT(allDone()));
    connect(coll.get(),
            SIGNAL(result(std::shared_ptr<const Kleo::Crypto::Task::Result>)),
            this,
            SLOT(result(std::shared_ptr<const Kleo::Crypto::Task::Result>)));
    connect(coll.get(), SIGNAL(started(std::shared_ptr<Kleo::Crypto::Task>)), this, SLOT(started(std::shared_ptr<Kleo::Crypto::Task>)));

    for (const std::shared_ptr<Task> &i : coll->tasks()) { // create labels for all tags in collection
        Q_ASSERT(i);
        QLabel *l = d->labelForTag(i->tag());
        Q_ASSERT(l);
        (void)l;
    }
    Q_EMIT completeChanged();
}

QLabel *NewResultPage::Private::labelForTag(const QString &tag)
{
    if (QLabel *const label = m_progressLabelByTag.value(tag)) {
        return label;
    }
    auto label = new QLabel;
    label->setTextFormat(Qt::RichText);
    label->setWordWrap(true);
    m_progressLabelLayout->addWidget(label);
    m_progressLabelByTag.insert(tag, label);
    return label;
}

bool NewResultPage::isComplete() const
{
    return d->m_resultList->isComplete();
}

#include "moc_newresultpage.cpp"
