/* -*- mode: c++; c-basic-offset:4 -*-
    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2007 Klarälvdalens Datakonsult AB

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include <config-kleopatra.h>

#include "wizardpage.h"

#include <KGuiItem>

using namespace Kleo::Crypto::Gui;

class WizardPage::Private
{
    friend class ::WizardPage;
    WizardPage *const q;

public:
    explicit Private(WizardPage *qq);
    ~Private();

private:
    bool commitPage = false;
    bool autoAdvance = false;
    QString title;
    QString subTitle;
    QString explanation;
    KGuiItem customNextButton;
};

WizardPage::Private::Private(WizardPage *qq)
    : q(qq)
{
}

WizardPage::Private::~Private()
{
}

WizardPage::WizardPage(QWidget *parent, Qt::WindowFlags f)
    : QWidget(parent, f)
    , d(new Private(this))
{
}

bool WizardPage::isCommitPage() const
{
    return d->commitPage;
}

void WizardPage::setCommitPage(bool commitPage)
{
    d->commitPage = commitPage;
}

bool WizardPage::autoAdvance() const
{
    return d->autoAdvance;
}

void WizardPage::setAutoAdvance(bool enabled)
{
    if (d->autoAdvance == enabled) {
        return;
    }
    d->autoAdvance = enabled;
    Q_EMIT autoAdvanceChanged();
}

QString WizardPage::title() const
{
    return d->title;
}

void WizardPage::setTitle(const QString &title)
{
    if (d->title == title) {
        return;
    }
    d->title = title;
    Q_EMIT titleChanged();
}

QString WizardPage::subTitle() const
{
    return d->subTitle;
}

void WizardPage::setSubTitle(const QString &subTitle)
{
    if (d->subTitle == subTitle) {
        return;
    }
    d->subTitle = subTitle;
    Q_EMIT subTitleChanged();
}

QString WizardPage::explanation() const
{
    return d->explanation;
}

void WizardPage::setExplanation(const QString &explanation)
{
    if (d->explanation == explanation) {
        return;
    }
    d->explanation = explanation;
    Q_EMIT explanationChanged();
}

KGuiItem WizardPage::customNextButton() const
{
    return d->customNextButton;
}
void WizardPage::setCustomNextButton(const KGuiItem &item)
{
    d->customNextButton = item;
}

WizardPage::~WizardPage()
{
}

bool WizardPage::onNext()
{
    return true;
}

#include "moc_wizardpage.cpp"
