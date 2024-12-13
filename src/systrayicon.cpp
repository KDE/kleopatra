/* -*- mode: c++; c-basic-offset:4 -*-
    systemtrayicon.cpp

    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2007 Klarälvdalens Datakonsult AB

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include <config-kleopatra.h>

#include "systrayicon.h"

#ifndef QT_NO_SYSTEMTRAYICON

#include "kleopatraapplication.h"
#include "mainwindow.h"

#include <smartcard/readerstatus.h>

#include <utils/clipboardmenu.h>

#include <commands/setinitialpincommand.h>

#include <KAboutApplicationDialog>
#include <KAboutData>
#include <KActionMenu>
#include <KLocalizedString>
#include <QEventLoopLocker>
#include <QIcon>

#include <QAction>
#include <QApplication>
#include <QMenu>
#include <QPointer>
#include <QSignalBlocker>

using namespace Kleo;
using namespace Kleo::Commands;
using namespace Kleo::SmartCard;

class SysTrayIcon::Private
{
    friend class ::SysTrayIcon;
    SysTrayIcon *const q;

public:
    explicit Private(SysTrayIcon *qq);
    ~Private();

private:
    void slotAbout()
    {
        if (!aboutDialog) {
            aboutDialog = new KAboutApplicationDialog(KAboutData::applicationData());
            aboutDialog->setAttribute(Qt::WA_DeleteOnClose);
        }

        if (aboutDialog->isVisible()) {
            aboutDialog->raise();
        } else {
            aboutDialog->show();
        }
    }

    void enableDisableActions()
    {
        openCertificateManagerAction.setEnabled(!q->mainWindow() || !q->mainWindow()->isVisible());
        setInitialPinAction.setEnabled(!firstCardWithNullPin.empty());

        q->setAttentionWanted(!firstCardWithNullPin.empty() && !q->attentionWindow());
    }

    void slotSetInitialPin()
    {
        if (!firstCardWithNullPin.empty()) {
            auto cmd = new SetInitialPinCommand(firstCardWithNullPin);
            q->setAttentionWindow(cmd->dialog());
            startCommand(cmd);
        }
    }

    void startCommand(Command *cmd)
    {
        Q_ASSERT(cmd);
        cmd->setParent(q->mainWindow());
        cmd->start();
    }

private:
    std::string firstCardWithNullPin;

    QMenu menu;
    QAction openCertificateManagerAction;
    QAction configureAction;
    QAction aboutAction;
    QAction quitAction;

    ClipboardMenu clipboardMenu;

    QMenu cardMenu;
    QAction updateCardStatusAction;
    QAction setInitialPinAction;

    QPointer<KAboutApplicationDialog> aboutDialog;
};

SysTrayIcon::Private::Private(SysTrayIcon *qq)
    : q(qq)
    , menu()
    , openCertificateManagerAction(i18nc("@action:inmenu", "&Open Certificate Manager..."), q)
    , configureAction(QIcon::fromTheme(QStringLiteral("configure")),
                      xi18nc("@action:inmenu", "&Configure <application>%1</application>...", KAboutData::applicationData().displayName()),
                      q)
    , aboutAction(QIcon::fromTheme(QStringLiteral("kleopatra")),
                  xi18nc("@action:inmenu", "&About <application>%1</application>...", KAboutData::applicationData().displayName()),
                  q)
    , quitAction(QIcon::fromTheme(QStringLiteral("application-exit")),
                 xi18nc("@action:inmenu", "&Shutdown <application>%1</application>", KAboutData::applicationData().displayName()),
                 q)
    , clipboardMenu(q)
    , cardMenu(i18nc("@title:menu", "SmartCard"))
    , updateCardStatusAction(i18nc("@action:inmenu", "Update Card Status"), q)
    , setInitialPinAction(i18nc("@action:inmenu", "Set NetKey v3 Initial PIN..."), q)
    , aboutDialog()
{
#ifdef Q_OS_WIN
    q->setNormalIcon(QIcon::fromTheme(QStringLiteral("kleopatra")));
#else
    q->setNormalIcon(QIcon::fromTheme(QStringLiteral("kleopatra-symbolic")));
#endif
    q->setAttentionIcon(QIcon::fromTheme(QStringLiteral("auth-sim-locked")));

    Q_SET_OBJECT_NAME(menu);
    Q_SET_OBJECT_NAME(openCertificateManagerAction);
    Q_SET_OBJECT_NAME(configureAction);
    Q_SET_OBJECT_NAME(aboutAction);
    Q_SET_OBJECT_NAME(quitAction);
    Q_SET_OBJECT_NAME(clipboardMenu);
    Q_SET_OBJECT_NAME(cardMenu);
    Q_SET_OBJECT_NAME(setInitialPinAction);

    connect(&openCertificateManagerAction, SIGNAL(triggered()), qApp, SLOT(openOrRaiseMainWindow()));
    connect(&configureAction, SIGNAL(triggered()), qApp, SLOT(openOrRaiseConfigDialog()));
    connect(&aboutAction, SIGNAL(triggered()), q, SLOT(slotAbout()));
    connect(&quitAction, &QAction::triggered, QCoreApplication::instance(), &QCoreApplication::quit);
    connect(&updateCardStatusAction, &QAction::triggered, ReaderStatus::instance(), &ReaderStatus::updateStatus);
    connect(&setInitialPinAction, SIGNAL(triggered()), q, SLOT(slotSetInitialPin()));

    menu.addAction(&openCertificateManagerAction);
    menu.addAction(&configureAction);
    menu.addAction(&aboutAction);
    menu.addSeparator();
    menu.addMenu(clipboardMenu.clipboardMenu()->menu());
    menu.addSeparator();
    menu.addMenu(&cardMenu);
    cardMenu.addAction(&updateCardStatusAction);
    cardMenu.addAction(&setInitialPinAction);
    menu.addSeparator();
    menu.addAction(&quitAction);

    q->setContextMenu(&menu);
    clipboardMenu.setMainWindow(q->mainWindow());
}

SysTrayIcon::Private::~Private()
{
}

SysTrayIcon::SysTrayIcon(QObject *p)
    : SystemTrayIcon(p)
    , d(new Private(this))
{
    slotEnableDisableActions();
}

SysTrayIcon::~SysTrayIcon()
{
}

MainWindow *SysTrayIcon::mainWindow() const
{
    return static_cast<MainWindow *>(SystemTrayIcon::mainWindow());
}

QDialog *SysTrayIcon::attentionWindow() const
{
    return static_cast<QDialog *>(SystemTrayIcon::attentionWindow());
}

void SysTrayIcon::doActivated()
{
    if (const QWidget *const aw = attentionWindow())
        if (aw->isVisible()) {
            return; // ignore clicks while an attention window is open.
        }
    if (!d->firstCardWithNullPin.empty()) {
        d->slotSetInitialPin();
    } else {
        // Toggle visibility of MainWindow
        KleopatraApplication::instance()->toggleMainWindowVisibility();
    }
}

void SysTrayIcon::setFirstCardWithNullPin(const std::string &serialNumber)
{
    if (d->firstCardWithNullPin == serialNumber) {
        return;
    }
    d->firstCardWithNullPin = serialNumber;
    slotEnableDisableActions();
}

void SysTrayIcon::slotEnableDisableActions()
{
    d->enableDisableActions();
}

#include "moc_systrayicon.cpp"

#endif // QT_NO_SYSTEMTRAYICON
