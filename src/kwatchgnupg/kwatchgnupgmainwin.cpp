/*
    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2001, 2002, 2004 Klarälvdalens Datakonsult AB

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include <config-kleopatra.h>

#include "kwatchgnupgmainwin.h"

#include "kwatchgnupgconfig.h"

#include <gpgme++/global.h>

#include <KActionCollection>
#include <KConfigGroup>
#include <KEditToolBar>
#include <KLocalizedString>
#include <KMessageBox>
#include <KProcess>
#include <KSharedConfig>
#include <KShortcutsDialog>
#include <KStandardAction>

#include <QAction>
#include <QApplication>
#include <QDateTime>
#include <QEventLoop>
#include <QFile>
#include <QFileDialog>
#include <QIcon>
#include <QTextEdit>
#include <QTextStream>

using namespace Qt::StringLiterals;

KWatchGnuPGMainWindow::KWatchGnuPGMainWindow(QWidget *parent)
    : KXmlGuiWindow(parent, Qt::Window)
    , mConfig(nullptr)
{
    createActions();
    createGUI();

    mCentralWidget = new QTextEdit(this);
    mCentralWidget->setReadOnly(true);

    setCentralWidget(mCentralWidget);

    mWatcher = new KProcess{this};
    connect(mWatcher, &QProcess::finished, this, &KWatchGnuPGMainWindow::slotWatcherExited);
    connect(mWatcher, &QProcess::readyReadStandardOutput, this, &KWatchGnuPGMainWindow::slotReadStdout);

    slotReadConfig();

    setAutoSaveSettings();
}

KWatchGnuPGMainWindow::~KWatchGnuPGMainWindow()
{
    disconnect(mWatcher, &QProcess::finished, this, &KWatchGnuPGMainWindow::slotWatcherExited);
    mWatcher->kill();
    mWatcher->waitForFinished(); // to avoid QProcess's warning "Destroyed while process ("watchgnupg") is still running."
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
    (void)KStandardActions::saveAs(this, &KWatchGnuPGMainWindow::slotSaveAs, actionCollection());
    (void)KStandardActions::quit(qApp, &QCoreApplication::quit, actionCollection());
    (void)KStandardActions::preferences(this, &KWatchGnuPGMainWindow::slotConfigure, actionCollection());
    (void)KStandardActions::keyBindings(this, &KWatchGnuPGMainWindow::configureShortcuts, actionCollection());
    (void)KStandardActions::configureToolbars(this, &KWatchGnuPGMainWindow::slotConfigureToolbars, actionCollection());
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
    disconnect(mWatcher, &QProcess::finished, this, &KWatchGnuPGMainWindow::slotWatcherExited);
    if (mWatcher->state() == QProcess::Running) {
        mWatcher->kill();
        while (mWatcher->state() == QProcess::Running) {
            qApp->processEvents(QEventLoop::ExcludeUserInputEvents);
        }
        mCentralWidget->append(i18n("[%1] Log stopped", QDateTime::currentDateTime().toString(Qt::ISODate)));
        mCentralWidget->ensureCursorVisible();
    }
    const QString watchgnupgPath = QFile::decodeName(GpgME::dirInfo("bindir")) + u"/watchgnupg"_s;
    if (!QFile::exists(watchgnupgPath)) {
        KMessageBox::error(this, i18n("The watchgnupg logging program could not be found.\nPlease make sure that watchgnupg is installed."));
        mCentralWidget->append(i18nc("[<timestamp>] Failed to start <path_of_watchgnupg>",
                                     "[%1] Failed to start %2",
                                     QDateTime::currentDateTime().toString(Qt::ISODate),
                                     watchgnupgPath));
        mCentralWidget->ensureCursorVisible();
        return;
    }
    mWatcher->setProgram(watchgnupgPath);
    mWatcher->setOutputChannelMode(KProcess::OnlyStdoutChannel);
    mWatcher->start();
    const bool ok = mWatcher->waitForStarted();
    if (!ok) {
        KMessageBox::error(this, i18n("The watchgnupg logging process could not be started.\nPlease make sure that watchgnupg is installed properly."));
        mCentralWidget->append(i18nc("[<timestamp>] Failed to start <path_of_watchgnupg>",
                                     "[%1] Failed to start %2",
                                     QDateTime::currentDateTime().toString(Qt::ISODate),
                                     watchgnupgPath));
        mCentralWidget->ensureCursorVisible();
        return;
    } else {
        mCentralWidget->append(i18n("[%1] Log started", QDateTime::currentDateTime().toString(Qt::ISODate)));
        mCentralWidget->ensureCursorVisible();
    }
    connect(mWatcher, &QProcess::finished, this, &KWatchGnuPGMainWindow::slotWatcherExited);
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
    }
}

void KWatchGnuPGMainWindow::slotSaveAs()
{
    const QString filename = QFileDialog::getSaveFileName(this, i18n("Save Log to File"));
    if (filename.isEmpty()) {
        return;
    }
    QFile file(filename);
    if (file.open(QIODevice::WriteOnly)) {
        QTextStream(&file) << mCentralWidget->document()->toPlainText();
    } else
        KMessageBox::information(this, i18n("Could not save file %1: %2", filename, file.errorString()));
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
    startWatcher();
}

#include "moc_kwatchgnupgmainwin.cpp"
