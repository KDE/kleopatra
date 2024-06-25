/*  dialogs/smartcardwindow.cpp

    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2024 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include "smartcardwindow.h"

#include <kleopatraapplication.h>
#include <mainwindow.h>

#include <smartcard/readerstatus.h>
#include <view/smartcardwidget.h>

#include <KActionCollection>
#include <KConfigGroup>
#include <KLocalizedString>
#include <KSharedConfig>
#include <KStandardAction>

#include <QLabel>
#include <QStatusBar>
#include <QVBoxLayout>

using namespace Kleo;
using namespace Kleo::SmartCard;

class SmartCardWindow::Private
{
    friend class ::SmartCardWindow;
    SmartCardWindow *const q;

public:
    Private(SmartCardWindow *qq);

private:
    void saveLayout();
    void restoreLayout(const QSize &defaultSize = {});
    void createActions();
    void setUpStatusBar();

private:
    KActionCollection *actionCollection = nullptr;
    SmartCardWidget *smartCardWidget = nullptr;
    QLabel *statusMessageLabel = nullptr;
};

SmartCardWindow::Private::Private(SmartCardWindow *qq)
    : q(qq)
    , actionCollection{new KActionCollection{qq, QStringLiteral("smartcards")}}
{
    actionCollection->setComponentDisplayName(i18n("Smart Card Management"));
    actionCollection->addAssociatedWidget(q);
}

void SmartCardWindow::Private::saveLayout()
{
    KConfigGroup configGroup(KSharedConfig::openStateConfig(), QLatin1String("SmartCardWindow"));
    configGroup.writeEntry("Size", q->size());
    configGroup.sync();
}

void SmartCardWindow::Private::restoreLayout(const QSize &defaultSize)
{
    const KConfigGroup configGroup(KSharedConfig::openStateConfig(), QLatin1String("SmartCardWindow"));
    const QSize size = configGroup.readEntry("Size", defaultSize);
    if (size.isValid()) {
        q->resize(size);
    }
}

void SmartCardWindow::Private::createActions()
{
    actionCollection->addAction(KStandardAction::StandardAction::Close, QStringLiteral("close"), q, &SmartCardWindow::close);
    smartCardWidget->createActions(actionCollection);
}

void SmartCardWindow::Private::setUpStatusBar()
{
    auto statusBar = q->statusBar();
    statusBar->setSizeGripEnabled(false);

    statusMessageLabel = new QLabel{statusBar};
    statusBar->addWidget(statusMessageLabel, 1);

    q->setStatusBar(statusBar);

    connect(ReaderStatus::instance(), &ReaderStatus::updateCardsStarted, q, [this]() {
        statusMessageLabel->setText(i18nc("@info:status", "Loading smart cards..."));
    });
    connect(ReaderStatus::instance(), &ReaderStatus::updateCardStarted, q, [this](const std::string &serialNumber, const std::string &appName) {
        const auto card = ReaderStatus::instance()->getCard(serialNumber, appName);
        if (card) {
            statusMessageLabel->setText(i18nc("@info:status", "Updating smart card %1...", card->displaySerialNumber()));
        } else {
            statusMessageLabel->setText(i18nc("@info:status", "Updating smart card..."));
        }
    });
    connect(ReaderStatus::instance(), &ReaderStatus::updateFinished, q, [this]() {
        statusMessageLabel->clear();
    });
    connect(ReaderStatus::instance(), &ReaderStatus::startingLearnCards, q, [this]() {
        statusMessageLabel->setText(i18nc("@info:status", "Importing certificates from smart cards..."));
    });
    connect(ReaderStatus::instance(), &ReaderStatus::cardsLearned, q, [this]() {
        statusMessageLabel->clear();
    });

    switch (ReaderStatus::instance()->currentAction()) {
    case ReaderStatus::UpdateCards: {
        statusMessageLabel->setText(i18nc("@info:status", "Loading smart cards..."));
        break;
    }
    case ReaderStatus::LearnCards: {
        statusMessageLabel->setText(i18nc("@info:status", "Importing certificates from smart cards..."));
        break;
    }
    case ReaderStatus::NoAction:
        break;
    }
}

SmartCardWindow::SmartCardWindow(QWidget *parent)
    : QMainWindow(parent)
    , d(new Private(this))
{
    setWindowTitle(i18nc("@title:window", "Manage Smart Cards"));

    d->smartCardWidget = new SmartCardWidget{this};
    d->smartCardWidget->setContentsMargins({});
    setCentralWidget(d->smartCardWidget);

    d->createActions();
    d->setUpStatusBar();

    // use size of main window as default size
    const auto mainWindow = KleopatraApplication::instance()->mainWindow();
    d->restoreLayout(mainWindow ? mainWindow->size() : QSize{1024, 500});

    // load the currently known cards and trigger an update
    d->smartCardWidget->showCards(ReaderStatus::instance()->getCards());
    d->smartCardWidget->reload();
}

SmartCardWindow::~SmartCardWindow()
{
    d->saveLayout();
}

#include "moc_smartcardwindow.cpp"
