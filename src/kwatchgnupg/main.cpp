/*
    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2001, 2002, 2004 Klarälvdalens Datakonsult AB

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include <config-kleopatra.h>

#include "aboutdata.h"
#include "kwatchgnupgmainwin.h"

#include "kwatchgnupg_debug.h"
#include <KCrash>
#include <KLocalizedString>
#include <KWindowSystem>

#include <KDSingleApplication>

#include <QApplication>
#include <QCommandLineParser>

int main(int argc, char **argv)
{
    QApplication app(argc, argv);

    KLocalizedString::setApplicationDomain(QByteArrayLiteral("kwatchgnupg"));

    AboutData aboutData;
    KAboutData::setApplicationData(aboutData);
    QGuiApplication::setWindowIcon(QIcon::fromTheme(QStringLiteral("org.kde.kwatchgnupg")));

    KCrash::initialize();

    QCommandLineParser parser;
    aboutData.setupCommandLine(&parser);
    parser.process(app);
    aboutData.processCommandLine(&parser);

    KDSingleApplication singleApp{&app};
    if (!singleApp.isPrimaryInstance()) {
        if (!singleApp.sendMessage("raise_window")) {
            qCWarning(KWATCHGNUPG_LOG) << "sending message to primary instance failed";
            return 1;
        }
        return 0;
    }

    auto mMainWin = new KWatchGnuPGMainWindow();
    mMainWin->show();

    QObject::connect(&singleApp, &KDSingleApplication::messageReceived, &app, [mMainWin](const QByteArray &message) {
        if (message == "raise_window") {
            mMainWin->show();
            mMainWin->activateWindow();
            mMainWin->raise();
            KWindowSystem::updateStartupId(mMainWin->windowHandle());
            KWindowSystem::activateWindow(mMainWin->windowHandle());
        }
    });

    return app.exec();
}
