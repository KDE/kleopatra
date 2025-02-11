/* -*- mode: c++; c-basic-offset:4 -*-
    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2007 Klarälvdalens Datakonsult AB

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include <config-kleopatra.h>

#include "wizard.h"
#include "wizardpage.h"

#include <utils/kleo_assert.h>

#include <Libkleo/Algorithm>

#include <KGuiItem>
#include <KLocalizedString>
#include <KStandardGuiItem>
#include <QPushButton>

#include "kleopatra_debug.h"
#include <QDialogButtonBox>
#include <QFrame>
#include <QLabel>
#include <QStackedWidget>
#include <QTimer>
#include <QVBoxLayout>

#include <map>
#include <set>

using namespace Kleo::Crypto::Gui;

class Wizard::Private
{
    friend class ::Wizard;
    Wizard *const q;

public:
    explicit Private(Wizard *qq);
    ~Private();

    void updateButtonStates();
    bool isLastPage(int id) const;
    int previousPage() const;
    void updateHeader();

private:
    std::vector<int> pageOrder;
    std::set<int> hiddenPages;
    std::map<int, WizardPage *> idToPage;
    int currentId = -1;
    QStackedWidget *const stack;
    QPushButton *nextButton = nullptr;
    QPushButton *backButton = nullptr;
    QPushButton *cancelButton = nullptr;
    KGuiItem finishItem;
    KGuiItem nextItem;
    QFrame *titleFrame = nullptr;
    QLabel *titleLabel = nullptr;
    QLabel *subTitleLabel = nullptr;
    QFrame *explanationFrame = nullptr;
    QLabel *explanationLabel = nullptr;
    QTimer *nextPageTimer = nullptr;
};

Wizard::Private::Private(Wizard *qq)
    : q(qq)
    , stack(new QStackedWidget)
{
    nextPageTimer = new QTimer(q);
    nextPageTimer->setInterval(0);
    connect(nextPageTimer, &QTimer::timeout, q, &Wizard::next);
    nextItem = KGuiItem(i18nc("@action:button", "&Next"));
    finishItem = KStandardGuiItem::ok();
    auto const top = new QVBoxLayout(q);
    top->setContentsMargins(0, 0, 0, 0);
    titleFrame = new QFrame;
    titleFrame->setFrameShape(QFrame::StyledPanel);
    titleFrame->setAutoFillBackground(true);
    titleFrame->setBackgroundRole(QPalette::Base);
    auto const titleLayout = new QVBoxLayout(titleFrame);
    titleLabel = new QLabel;
    titleLayout->addWidget(titleLabel);
    subTitleLabel = new QLabel;
    subTitleLabel->setWordWrap(true);
    titleLayout->addWidget(subTitleLabel);
    top->addWidget(titleFrame);
    titleFrame->setVisible(false);

    top->addWidget(stack);

    explanationFrame = new QFrame;
    explanationFrame->setFrameShape(QFrame::StyledPanel);
    explanationFrame->setAutoFillBackground(true);
    explanationFrame->setBackgroundRole(QPalette::Base);
    auto const explanationLayout = new QVBoxLayout(explanationFrame);
    explanationLabel = new QLabel;
    explanationLabel->setWordWrap(true);
    explanationLayout->addWidget(explanationLabel);
    top->addWidget(explanationFrame);
    explanationFrame->setVisible(false);

    auto buttonWidget = new QWidget;
    auto buttonLayout = new QHBoxLayout(buttonWidget);
    auto const box = new QDialogButtonBox;

    cancelButton = box->addButton(QDialogButtonBox::Cancel);
    q->connect(cancelButton, &QPushButton::clicked, q, &Wizard::reject);

    backButton = new QPushButton;
    backButton->setText(i18n("Back"));
    q->connect(backButton, &QPushButton::clicked, q, &Wizard::back);
    box->addButton(backButton, QDialogButtonBox::ActionRole);

    nextButton = new QPushButton;
    KGuiItem::assign(nextButton, nextItem);
    q->connect(nextButton, &QPushButton::clicked, q, &Wizard::next);
    box->addButton(nextButton, QDialogButtonBox::ActionRole);
    buttonLayout->addWidget(box);

    top->addWidget(buttonWidget);

    q->connect(q, &Wizard::rejected, q, &Wizard::canceled);
}

Wizard::Private::~Private()
{
    qCDebug(KLEOPATRA_LOG) << q << __func__;
}

bool Wizard::Private::isLastPage(int id) const
{
    return !pageOrder.empty() ? pageOrder.back() == id : false;
}

void Wizard::Private::updateButtonStates()
{
    const bool isLast = isLastPage(currentId);
    const bool canGoToNext = q->canGoToNextPage();
    WizardPage *const page = q->page(currentId);
    const KGuiItem customNext = page ? page->customNextButton() : KGuiItem();
    if (customNext.text().isEmpty() && customNext.icon().isNull()) {
        KGuiItem::assign(nextButton, isLast ? finishItem : nextItem);
    } else {
        KGuiItem::assign(nextButton, customNext);
    }
    nextButton->setEnabled(canGoToNext);
    cancelButton->setEnabled(!isLast || !canGoToNext);
    backButton->setEnabled(q->canGoToPreviousPage());
    if (page && page->autoAdvance() && page->isComplete()) {
        nextPageTimer->start();
    }
}

void Wizard::Private::updateHeader()
{
    WizardPage *const widget = q->page(currentId);
    Q_ASSERT(!widget || stack->indexOf(widget) != -1);
    if (widget) {
        stack->setCurrentWidget(widget);
    }
    const QString title = widget ? widget->title() : QString();
    const QString subTitle = widget ? widget->subTitle() : QString();
    const QString explanation = widget ? widget->explanation() : QString();
    titleFrame->setVisible(!title.isEmpty() || !subTitle.isEmpty() || !explanation.isEmpty());
    titleLabel->setVisible(!title.isEmpty());
    titleLabel->setText(title);
    subTitleLabel->setText(subTitle);
    subTitleLabel->setVisible(!subTitle.isEmpty());
    explanationFrame->setVisible(!explanation.isEmpty());
    explanationLabel->setVisible(!explanation.isEmpty());
    explanationLabel->setText(explanation);
    q->resize(q->sizeHint().expandedTo(q->size()));
}

Wizard::Wizard(QWidget *parent, Qt::WindowFlags f)
    : QDialog(parent, f)
    , d(new Private(this))
{
}

Wizard::~Wizard()
{
    qCDebug(KLEOPATRA_LOG) << this << __func__;
}

void Wizard::setPage(int id, WizardPage *widget)
{
    kleo_assert(id != InvalidPage);
    kleo_assert(d->idToPage.find(id) == d->idToPage.end());
    d->idToPage[id] = widget;
    d->stack->addWidget(widget);
    connect(widget, SIGNAL(completeChanged()), this, SLOT(updateButtonStates()));
    connect(widget, SIGNAL(titleChanged()), this, SLOT(updateHeader()));
    connect(widget, SIGNAL(subTitleChanged()), this, SLOT(updateHeader()));
    connect(widget, SIGNAL(explanationChanged()), this, SLOT(updateHeader()));
    connect(widget, SIGNAL(autoAdvanceChanged()), this, SLOT(updateButtonStates()));
    connect(widget, SIGNAL(windowTitleChanged(QString)), this, SLOT(setWindowTitle(QString)));
}

void Wizard::setPageOrder(const std::vector<int> &pageOrder)
{
    d->pageOrder = pageOrder;
    d->hiddenPages.clear();
    if (pageOrder.empty()) {
        return;
    }
    setCurrentPage(pageOrder.front());
}

void Wizard::setCurrentPage(int id)
{
    d->currentId = id;
    if (id == InvalidPage) {
        return;
    }
    d->updateHeader();
    d->updateButtonStates();
}

void Wizard::setPageVisible(int id, bool visible)
{
    if (visible) {
        d->hiddenPages.erase(id);
    } else {
        d->hiddenPages.insert(id);
    }
    if (currentPage() == id && !visible) {
        next();
    }
}

int Wizard::currentPage() const
{
    return d->currentId;
}

bool Wizard::canGoToNextPage() const
{
    const WizardPage *const current = currentPageWidget();
    return current ? current->isComplete() : false;
}

bool Wizard::canGoToPreviousPage() const
{
    const int prev = d->previousPage();
    if (prev == InvalidPage) {
        return false;
    }
    const WizardPage *const prevPage = page(prev);
    Q_ASSERT(prevPage);
    return !prevPage->isCommitPage();
}

void Wizard::next()
{
    WizardPage *const current = currentPageWidget();
    if (current) {
        if (!current->onNext()) {
            return;
        }
    }
    onNext(d->currentId);
    auto it = Kleo::binary_find(d->pageOrder.begin(), d->pageOrder.end(), d->currentId);
    Q_ASSERT(it != d->pageOrder.end());

    do {
        ++it;
    } while (d->hiddenPages.find(*it) != d->hiddenPages.end());

    if (it == d->pageOrder.end()) { // "Finish"
        d->currentId = InvalidPage;
        close();
    } else { // "next"
        setCurrentPage(*it);
    }
}

int Wizard::Private::previousPage() const
{
    if (pageOrder.empty()) {
        return InvalidPage;
    }

    auto it = Kleo::binary_find(pageOrder.begin(), pageOrder.end(), currentId);
    if (it == pageOrder.begin() || it == pageOrder.end()) {
        return InvalidPage;
    }

    do {
        --it;
    } while (it != pageOrder.begin() && hiddenPages.find(*it) != hiddenPages.end());
    return *it;
}

void Wizard::back()
{
    onBack(d->currentId);
    const int prev = d->previousPage();
    if (prev == InvalidPage) {
        return;
    }
    setCurrentPage(prev);
}

const WizardPage *Wizard::page(int id) const
{
    if (id == InvalidPage) {
        return nullptr;
    }

    const auto it = d->idToPage.find(id);
    kleo_assert(it != d->idToPage.end());
    return (*it).second;
}

const WizardPage *Wizard::currentPageWidget() const
{
    return page(d->currentId);
}

WizardPage *Wizard::currentPageWidget()
{
    return page(d->currentId);
}

void Wizard::onNext(int currentId)
{
    Q_UNUSED(currentId)
}

void Wizard::onBack(int currentId)
{
    Q_UNUSED(currentId)
}

WizardPage *Wizard::page(int id)
{
    if (id == InvalidPage) {
        return nullptr;
    }

    const auto it = d->idToPage.find(id);
    kleo_assert(it != d->idToPage.end());
    return (*it).second;
}

#include "moc_wizard.cpp"
