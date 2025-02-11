/*
    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2001, 2002, 2004 Klarälvdalens Datakonsult AB

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#pragma once

#include <KXmlGuiWindow>

#include <QProcess>

class KWatchGnuPGConfig;
class KProcess;
class QTextEdit;

class KWatchGnuPGMainWindow : public KXmlGuiWindow
{
    Q_OBJECT
public:
    explicit KWatchGnuPGMainWindow(QWidget *parent = nullptr);
    ~KWatchGnuPGMainWindow() override;

private Q_SLOTS:
    void slotWatcherExited(int, QProcess::ExitStatus);
    void slotReadStdout();

    void slotSaveAs();
    void slotClear();

    void slotConfigure();
    void slotConfigureToolbars();
    void configureShortcuts();
    void slotReadConfig();

private:
    void createActions();
    void startWatcher();
    void setGnuPGConfig();

    KProcess *mWatcher;

    QTextEdit *mCentralWidget;
    KWatchGnuPGConfig *mConfig;
};
