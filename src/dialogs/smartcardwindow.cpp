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

#include <KConfigGroup>
#include <KLocalizedString>
#include <KSharedConfig>
#include <KStandardAction>

#include <QVBoxLayout>

using namespace Kleo;
using namespace Kleo::SmartCard;

class SmartCardWindow::Private
{
    friend class ::SmartCardWindow;
    SmartCardWindow *const q;

public:
    Private(SmartCardWindow *qq)
        : q(qq)
    {
    }

private:
    void saveLayout();
    void restoreLayout(const QSize &defaultSize = {});

private:
    SmartCardWidget *smartCardWidget = nullptr;
};

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

SmartCardWindow::SmartCardWindow(QWidget *parent)
    : QMainWindow(parent)
    , d(new Private(this))
{
    setWindowTitle(i18nc("@title:window", "Manage Smart Cards"));

    d->smartCardWidget = new SmartCardWidget{this};
    d->smartCardWidget->setContentsMargins({});
    setCentralWidget(d->smartCardWidget);

    addAction(KStandardAction::close(this, &SmartCardWindow::close, this));
    {
        auto action = KStandardAction::redisplay(
            this,
            [this]() {
                d->smartCardWidget->reload();
            },
            this);
        action->setToolTip(i18nc("@info:tooltip", "Reload smart cards"));
        addAction(action);
    }

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
