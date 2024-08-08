/*
    main.cpp

    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2001, 2002, 2004 Klarälvdalens Datakonsult AB

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include <config-kleopatra.h>

#include "aboutdata.h"
#include "kwatchgnupgmainwin.h"
#include "utils/kuniqueservice.h"

#include "kwatchgnupg_debug.h"
#include <KCrash>
#include <KLocalizedString>
#include <QApplication>
#include <QCommandLineParser>

int main(int argc, char **argv)
{
    QApplication app(argc, argv);

    KLocalizedString::setApplicationDomain(QByteArrayLiteral("kwatchgnupg"));

    AboutData aboutData;
    KAboutData::setApplicationData(aboutData);

    KCrash::initialize();

    QCommandLineParser parser;
    aboutData.setupCommandLine(&parser);
    parser.process(app);
    aboutData.processCommandLine(&parser);

    KUniqueService service;

    auto mMainWin = new KWatchGnuPGMainWindow();
    mMainWin->show();
    return app.exec();
}
