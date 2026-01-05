/*
    This file is part of Kleopatra's test suite.
    SPDX-FileCopyrightText: 2022 Carlo Vanini <silhusk@gmail.com>

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include <utils/path-helper.h>

#include <QDebug>
#include <QTest>

class PathHelperTest : public QObject
{
    Q_OBJECT

private Q_SLOTS:
    void testStripSuffix_data();
    void testStripSuffix();
};

void PathHelperTest::testStripSuffix_data()
{
    QTest::addColumn<QString>("fileName");
    QTest::addColumn<QString>("baseName");

    QTest::newRow("absolute path") //
        << QString::fromLatin1("/home/user/test.sig") //
        << QString::fromLatin1("/home/user/test");
    QTest::newRow("relative path") //
        << QString::fromLatin1("home/user.name/test.sig") //
        << QString::fromLatin1("home/user.name/test");
    QTest::newRow("file name") //
        << QString::fromLatin1("t.sig") //
        << QString::fromLatin1("./t");
    QTest::newRow("short extension") //
        << QString::fromLatin1("/path/to/test.s") //
        << QString::fromLatin1("/path/to/test");
    QTest::newRow("long extension") //
        << QString::fromLatin1("/test.sign") //
        << QString::fromLatin1("/test");
    QTest::newRow("multiple extension") //
        << QString::fromLatin1("some/test.tar.gz.asc") //
        << QString::fromLatin1("some/test.tar.gz");
}

void PathHelperTest::testStripSuffix()
{
    QFETCH(QString, fileName);
    QFETCH(QString, baseName);

    QCOMPARE(Kleo::stripSuffix(fileName), baseName);
}

QTEST_MAIN(PathHelperTest)
#include "pathhelpertest.moc"
