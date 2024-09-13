/*
    This file is part of Kleopatra's test suite.
    SPDX-FileCopyrightText: 2007 Klarälvdalens Datakonsult AB

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#pragma once

#include <KAboutData>
#include <KLocalizedString>
#include <QDir>
#include <QTest>
#ifndef KLEO_TEST_GNUPGHOME
#error KLEO_TEST_GNUPGHOME not defined!
#endif

// based on qtest_kde.h
#define QTEST_KLEOMAIN(TestObject)                                                                                                                             \
    int main(int argc, char *argv[])                                                                                                                           \
    {                                                                                                                                                          \
        qputenv("GNUPGHOME", KLEO_TEST_GNUPGHOME);                                                                                                             \
        qputenv("LC_ALL", "C");                                                                                                                                \
        qputenv("KDEHOME", QFile::encodeName(QDir::homePath() + QLatin1StringView("/.kde-unit-test")));                                                        \
        KAboutData aboutData(QLatin1StringView("qttest"), i18n("qttest"), QLatin1StringView("version"));                                                       \
        QApplication app(argc, argv);                                                                                                                          \
        app.setApplicationName(QLatin1StringView("qttest"));                                                                                                   \
        TestObject tc;                                                                                                                                         \
        return QTest::qExec(&tc, argc, argv);                                                                                                                  \
    }
