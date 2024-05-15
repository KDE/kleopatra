/*
    kwatchgnupgmainwin.cpp

    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2001, 2002, 2004 Klar �vdalens Datakonsult AB

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include <config-kleopatra.h>

#include "kwatchgnupgmainwin.h"

#include "kwatchgnupg.h"
#include "kwatchgnupgconfig.h"
#include "tray.h"

#include <QGpgME/CryptoConfig>
#include <QGpgME/Protocol>

#include <QTextEdit>

#include <KActionCollection>
#include <KConfig>
#include <KConfigGroup>
#include <KEditToolBar>
#include <KLocalizedString>
#include <KMessageBox>
#include <KProcess>
#include <KShortcutsDialog>
#include <KStandardAction>
#include <QAction>
#include <QApplication>
#include <QIcon>

#include <KSharedConfig>
#include <QDateTime>
#include <QEventLoop>
#include <QFileDialog>
#include <QTextStream>

KWatchGnuPGMainWindow::KWatchGnuPGMainWindow(QWidget *parent)
    : KXmlGuiWindow(parent, Qt::Window)
    , mConfig(nullptr)
{
    createActions();
    createGUI();

    mCentralWidget = new QTextEdit(this);
    mCentralWidget->setReadOnly(true);

    setCentralWidget(mCentralWidget);

    mWatcher = new KProcess;
    connect(mWatcher, SIGNAL(finished(int, QProcess::ExitStatus)), this, SLOT(slotWatcherExited(int, QProcess::ExitStatus)));

    connect(mWatcher, &QProcess::readyReadStandardOutput, this, &KWatchGnuPGMainWindow::slotReadStdout);

    slotReadConfig();
    mSysTray = new KWatchGnuPGTray(this);
    QAction *act = mSysTray->action(QStringLiteral("quit"));
    if (act) {
        connect(act, &QAction::triggered, this, &KWatchGnuPGMainWindow::slotQuit);
    }

    setAutoSaveSettings();
}

KWatchGnuPGMainWindow::~KWatchGnuPGMainWindow()
{
    delete mWatcher;
}

void KWatchGnuPGMainWindow::slotClear()
{
    mCentralWidget->clear();
    mCentralWidget->append(i18n("[%1] Log cleared", QDateTime::currentDateTime().toString(Qt::ISODate)));
}

void KWatchGnuPGMainWindow::createActions()
{
    QAction *action = actionCollection()->addAction(QStringLiteral("clear_log"));
    action->setIcon(QIcon::fromTheme(QStringLiteral("edit-clear-history")));
    action->setText(i18n("C&lear History"));
    connect(action, &QAction::triggered, this, &KWatchGnuPGMainWindow::slotClear);
    actionCollection()->setDefaultShortcut(action, QKeySequence(Qt::CTRL | Qt::Key_L));
    (void)KStandardAction::saveAs(this, &KWatchGnuPGMainWindow::slotSaveAs, actionCollection());
    (void)KStandardAction::close(this, &KWatchGnuPGMainWindow::close, actionCollection());
    (void)KStandardAction::quit(this, &KWatchGnuPGMainWindow::slotQuit, actionCollection());
    (void)KStandardAction::preferences(this, &KWatchGnuPGMainWindow::slotConfigure, actionCollection());
    (void)KStandardAction::keyBindings(this, &KWatchGnuPGMainWindow::configureShortcuts, actionCollection());
    (void)KStandardAction::configureToolbars(this, &KWatchGnuPGMainWindow::slotConfigureToolbars, actionCollection());
}

void KWatchGnuPGMainWindow::configureShortcuts()
{
    KShortcutsDialog::showDialog(actionCollection(), KShortcutsEditor::LetterShortcutsAllowed, this);
}

void KWatchGnuPGMainWindow::slotConfigureToolbars()
{
    KEditToolBar dlg(factory());
    dlg.exec();
}

void KWatchGnuPGMainWindow::startWatcher()
{
    disconnect(mWatcher, SIGNAL(finished(int, QProcess::ExitStatus)), this, SLOT(slotWatcherExited(int, QProcess::ExitStatus)));
    if (mWatcher->state() == QProcess::Running) {
        mWatcher->kill();
        while (mWatcher->state() == QProcess::Running) {
            qApp->processEvents(QEventLoop::ExcludeUserInputEvents);
        }
        mCentralWidget->append(i18n("[%1] Log stopped", QDateTime::currentDateTime().toString(Qt::ISODate)));
        mCentralWidget->ensureCursorVisible();
    }
    mWatcher->clearProgram();

    {
        const KConfigGroup config(KSharedConfig::openConfig(), QStringLiteral("WatchGnuPG"));
        *mWatcher << config.readEntry("Executable", WATCHGNUPGBINARY);
        *mWatcher << QStringLiteral("--force");
        *mWatcher << config.readEntry("Socket", WATCHGNUPGSOCKET);
    }

    mWatcher->setOutputChannelMode(KProcess::OnlyStdoutChannel);
    mWatcher->start();
    const bool ok = mWatcher->waitForStarted();
    if (!ok) {
        KMessageBox::error(this,
                           i18n("The watchgnupg logging process could not be started.\nPlease install watchgnupg somewhere in your $PATH.\nThis log window is "
                                "unable to display any useful information."));
    } else {
        mCentralWidget->append(i18n("[%1] Log started", QDateTime::currentDateTime().toString(Qt::ISODate)));
        mCentralWidget->ensureCursorVisible();
    }
    connect(mWatcher, SIGNAL(finished(int, QProcess::ExitStatus)), this, SLOT(slotWatcherExited(int, QProcess::ExitStatus)));
}

void KWatchGnuPGMainWindow::setGnuPGConfig()
{
    QStringList logclients;
    // Get config object
    QGpgME::CryptoConfig *const cconfig = QGpgME::cryptoConfig();
    if (!cconfig) {
        return;
    }
    KConfigGroup config(KSharedConfig::openConfig(), QStringLiteral("WatchGnuPG"));
    const QStringList comps = cconfig->componentList();
    for (QStringList::const_iterator it = comps.constBegin(); it != comps.constEnd(); ++it) {
        const QGpgME::CryptoConfigComponent *const comp = cconfig->component(*it);
        Q_ASSERT(comp);
        {
            QGpgME::CryptoConfigEntry *const entry = cconfig->entry(comp->name(), QStringLiteral("log-file"));
            if (entry) {
                entry->setStringValue(QLatin1StringView("socket://") + config.readEntry("Socket", WATCHGNUPGSOCKET));
                logclients << QStringLiteral("%1 (%2)").arg(*it, comp->description());
            }
        }
        {
            QGpgME::CryptoConfigEntry *const entry = cconfig->entry(comp->name(), QStringLiteral("debug-level"));
            if (entry) {
                entry->setStringValue(config.readEntry("LogLevel", "basic"));
            }
        }
    }
    cconfig->sync(true);
    if (logclients.isEmpty()) {
        KMessageBox::error(nullptr, i18n("There are no components available that support logging."));
    }
}

void KWatchGnuPGMainWindow::slotWatcherExited(int, QProcess::ExitStatus)
{
    if (KMessageBox::questionTwoActions(this,
                                        i18n("The watchgnupg logging process died.\nDo you want to try to restart it?"),
                                        QString(),
                                        KGuiItem(i18nc("@action:button", "Try Restart")),
                                        KGuiItem(i18nc("@action:button", "Do Not Try")))
        == KMessageBox::ButtonCode::PrimaryAction) {
        mCentralWidget->append(i18n("====== Restarting logging process ====="));
        mCentralWidget->ensureCursorVisible();
        startWatcher();
    } else {
        KMessageBox::error(this, i18n("The watchgnupg logging process is not running.\nThis log window is unable to display any useful information."));
    }
}

void KWatchGnuPGMainWindow::slotReadStdout()
{
    if (!mWatcher) {
        return;
    }
    while (mWatcher->canReadLine()) {
        QString str = QString::fromUtf8(mWatcher->readLine());
        if (str.endsWith(QLatin1Char('\n'))) {
            str.chop(1);
        }
        if (str.endsWith(QLatin1Char('\r'))) {
            str.chop(1);
        }
        mCentralWidget->append(str);
        mCentralWidget->ensureCursorVisible();
        if (!isVisible()) {
            // Change tray icon to show something happened
            // PENDING(steffen)
            mSysTray->setAttention(true);
        }
    }
}

void KWatchGnuPGMainWindow::show()
{
    mSysTray->setAttention(false);
    KMainWindow::show();
}

void KWatchGnuPGMainWindow::slotSaveAs()
{
    const QString filename = QFileDialog::getSaveFileName(this, i18n("Save Log to File"));
    if (filename.isEmpty()) {
        return;
    }
    QFile file(filename);
    if (file.open(QIODevice::WriteOnly)) {
        QTextStream(&file) << mCentralWidget->document()->toRawText();
    } else
        KMessageBox::information(this, i18n("Could not save file %1: %2", filename, file.errorString()));
}

void KWatchGnuPGMainWindow::slotQuit()
{
    disconnect(mWatcher, SIGNAL(finished(int, QProcess::ExitStatus)), this, SLOT(slotWatcherExited(int, QProcess::ExitStatus)));
    mWatcher->kill();
    qApp->quit();
}

void KWatchGnuPGMainWindow::slotConfigure()
{
    if (!mConfig) {
        mConfig = new KWatchGnuPGConfig(this);
        mConfig->setObjectName(QLatin1StringView("config dialog"));
        connect(mConfig, &KWatchGnuPGConfig::reconfigure, this, &KWatchGnuPGMainWindow::slotReadConfig);
    }
    mConfig->loadConfig();
    mConfig->exec();
}

void KWatchGnuPGMainWindow::slotReadConfig()
{
    const KConfigGroup config(KSharedConfig::openConfig(), QStringLiteral("LogWindow"));
    const int maxLogLen = config.readEntry("MaxLogLen", 10000);
    mCentralWidget->document()->setMaximumBlockCount(maxLogLen < 1 ? -1 : maxLogLen);
    setGnuPGConfig();
    startWatcher();
}

bool KWatchGnuPGMainWindow::queryClose()
{
    if (!qApp->isSavingSession()) {
        hide();
        return false;
    }
    return KMainWindow::queryClose();
}

#include "moc_kwatchgnupgmainwin.cpp"
