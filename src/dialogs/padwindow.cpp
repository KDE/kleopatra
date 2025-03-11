// SPDX-FileCopyrightText: 2025 g10 Code GmbH
// SPDX-FileContributor: Tobias Fella <tobias.fella@gnupg.com>
// SPDX-License-Identifier: GPL-2.0-or-later

#include "padwindow.h"

#include "kleopatraapplication.h"
#include "mainwindow.h"
#include "view/padwidget.h"

#include <KConfigGroup>
#include <KLocalizedString>
#include <KSharedConfig>

using namespace Kleo;

class PadWindow::Private
{
    friend class ::PadWindow;
    PadWindow *const q;

public:
    explicit Private(PadWindow *qq);

private:
    void saveLayout();
    void restoreLayout(const QSize &defaultSize = {});

private:
    PadWidget *padWidget = nullptr;
};

PadWindow::Private::Private(PadWindow *qq)
    : q(qq)
{
}

void PadWindow::Private::saveLayout()
{
    KConfigGroup configGroup(KSharedConfig::openStateConfig(), QLatin1StringView("PadWindow"));
    configGroup.writeEntry("Size", q->size());
    configGroup.sync();
}

void PadWindow::Private::restoreLayout(const QSize &defaultSize)
{
    const KConfigGroup configGroup(KSharedConfig::openStateConfig(), QLatin1StringView("PadWindow"));
    const QSize size = configGroup.readEntry("Size", defaultSize);
    if (size.isValid()) {
        q->resize(size);
    }
}

PadWindow::PadWindow(QWidget *parent)
    : QMainWindow(parent)
    , d(new Private(this))
{
    setWindowTitle(i18nc("@title:window", "Notepad"));

    d->padWidget = new PadWidget{this};
    d->padWidget->setContentsMargins({});
    setCentralWidget(d->padWidget);

    // use size of main window as default size
    const auto mainWindow = KleopatraApplication::instance()->mainWindow();
    d->restoreLayout(mainWindow ? mainWindow->size() : QSize{1024, 500});
}

PadWindow::~PadWindow()
{
    d->saveLayout();
}

#include "moc_padwindow.cpp"
