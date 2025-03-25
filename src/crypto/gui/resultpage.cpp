/*
    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2008 Klarälvdalens Datakonsult AB

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include <config-kleopatra.h>

#include "resultitemwidget.h"
#include "resultlistwidget.h"
#include "resultpage.h"

#include <crypto/taskcollection.h>

#include <KLocalizedString>

#include <QCheckBox>
#include <QHash>
#include <QLabel>
#include <QProgressBar>
#include <QVBoxLayout>

using namespace Kleo;
using namespace Kleo::Crypto;
using namespace Kleo::Crypto::Gui;

class ResultPage::Private
{
    ResultPage *const q;

public:
    explicit Private(ResultPage *qq);

    void progress(int progress, int total);
    void result(const std::shared_ptr<const Task::Result> &result);
    void started(const std::shared_ptr<Task> &result);
    void allDone();
    QLabel *labelForTag(const QString &tag);

    std::shared_ptr<TaskCollection> m_tasks;
    QProgressBar *m_progressBar;
    QHash<QString, QLabel *> m_progressLabelByTag;
    QVBoxLayout *m_progressLabelLayout;
    int m_lastErrorItemIndex = 0;
    ResultListWidget *m_resultList;
    QCheckBox *m_autoCloseCB;
};

ResultPage::Private::Private(ResultPage *qq)
    : q(qq)
{
    QBoxLayout *const layout = new QVBoxLayout(q);
    auto const labels = new QWidget;
    m_progressLabelLayout = new QVBoxLayout(labels);
    layout->addWidget(labels);
    m_progressBar = new QProgressBar;
    layout->addWidget(m_progressBar);
    m_resultList = new ResultListWidget;
    layout->addWidget(m_resultList);
    m_autoCloseCB = new QCheckBox;
    m_autoCloseCB->setText(i18nc("@option:check", "Close window automatically on success"));
    m_autoCloseCB->setChecked(false);
    layout->addWidget(m_autoCloseCB);
}

void ResultPage::Private::progress(int progress, int total)
{
    Q_ASSERT(progress >= 0);
    Q_ASSERT(total >= 0);
    m_progressBar->setRange(0, total);
    m_progressBar->setValue(progress);
}

void ResultPage::Private::allDone()
{
    Q_ASSERT(m_tasks);
    q->setAutoAdvance(m_autoCloseCB->isChecked() && !m_tasks->errorOccurred());
    m_progressBar->setVisible(false);
    m_tasks.reset();
    const auto progressLabelByTagKeys{m_progressLabelByTag.keys()};
    for (const QString &i : progressLabelByTagKeys) {
        m_progressLabelByTag.value(i)->clear();
    }
    Q_EMIT q->completeChanged();
}

void ResultPage::Private::result(const std::shared_ptr<const Task::Result> &)
{
}

void ResultPage::Private::started(const std::shared_ptr<Task> &task)
{
    Q_ASSERT(task);
    const QString tag = task->tag();
    QLabel *const label = labelForTag(tag);
    Q_ASSERT(label);
    if (tag.isEmpty()) {
        label->setText(i18nc("number, operation description", "Operation %1: %2", m_tasks->numberOfCompletedTasks() + 1, task->label()));
    } else {
        label->setText(i18nc(R"(tag( "OpenPGP" or "CMS"),  operation description)", "%1: %2", tag, task->label()));
    }
}

ResultPage::ResultPage(QWidget *parent, Qt::WindowFlags flags)
    : WizardPage(parent, flags)
    , d(new Private(this))
{
    setTitle(i18n("<b>Results</b>"));
}

ResultPage::~ResultPage()
{
}

bool ResultPage::keepOpenWhenDone() const
{
    return !d->m_autoCloseCB->isChecked();
}

void ResultPage::setKeepOpenWhenDone(bool keep)
{
    d->m_autoCloseCB->setChecked(!keep);
}

void ResultPage::setTaskCollection(const std::shared_ptr<TaskCollection> &coll)
{
    Q_ASSERT(!d->m_tasks);
    if (d->m_tasks == coll) {
        return;
    }
    d->m_tasks = coll;
    Q_ASSERT(d->m_tasks);
    d->m_resultList->setTaskCollection(coll);
    connect(d->m_tasks.get(), &TaskCollection::progress, this, [this](int current, int total) {
        d->progress(current, total);
    });
    connect(d->m_tasks.get(), SIGNAL(done()), this, SLOT(allDone()));
    connect(d->m_tasks.get(),
            SIGNAL(result(std::shared_ptr<const Kleo::Crypto::Task::Result>)),
            this,
            SLOT(result(std::shared_ptr<const Kleo::Crypto::Task::Result>)));
    connect(d->m_tasks.get(), SIGNAL(started(std::shared_ptr<Kleo::Crypto::Task>)), this, SLOT(started(std::shared_ptr<Kleo::Crypto::Task>)));

    for (const std::shared_ptr<Task> &i : d->m_tasks->tasks()) { // create labels for all tags in collection
        Q_ASSERT(i && d->labelForTag(i->tag()));
        Q_UNUSED(i)
    }
    Q_EMIT completeChanged();
}

QLabel *ResultPage::Private::labelForTag(const QString &tag)
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

bool ResultPage::isComplete() const
{
    return d->m_tasks ? d->m_tasks->allTasksCompleted() : true;
}

#include "moc_resultpage.cpp"
