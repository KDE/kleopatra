/*
    This file is part of Kleopatra's test suite.
    SPDX-FileCopyrightText: 2022 Carlo Vanini <silhusk@gmail.com>
    SPDX-FileCopyrightText: 2026 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include <utils/path-helper.h>

#include <QDebug>
#include <QTest>

using namespace Qt::Literals::StringLiterals;

class PathHelperTest : public QObject
{
    Q_OBJECT

private Q_SLOTS:
    void testStripSuffix_data();
    void testStripSuffix();

    void testSanitizedFileName_data();
    void testSanitizedFileName();

    void testPrettifiedDotFileName_data();
    void testPrettifiedDotFileName();
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

void PathHelperTest::testSanitizedFileName_data()
{
    QTest::addColumn<QString>("fileName");
    QTest::addColumn<QString>("sanitizedFileName");

    QTest::newRow("digits") << u"0123456789"_s << u"0123456789"_s;
    QTest::newRow("upper case letters") << u"ABCDEFGHIJKLMNOPQRSTUVWXYZ"_s << u"ABCDEFGHIJKLMNOPQRSTUVWXYZ"_s;
    QTest::newRow("lower case letters") << u"abcdefghijklmnopqrstuvwxyz"_s << u"abcdefghijklmnopqrstuvwxyz"_s;
    QTest::newRow("bad characters: space / \\ : * ? \" < > | -> to be replaced") << u" //\\:*?\"<>||<>\"?*://\\ "_s << u"______________________"_s;
    QTest::newRow("other printable characters") << u"!#$%&'()+,-.;=[]^_{}~"_s << u"!#$%&'()+,-.;=[]^_{}~"_s;
}

void PathHelperTest::testSanitizedFileName()
{
    QFETCH(QString, fileName);
    QFETCH(QString, sanitizedFileName);

    QCOMPARE(Kleo::sanitizedFileName(std::move(fileName)), sanitizedFileName);
}

void PathHelperTest::testPrettifiedDotFileName_data()
{
    QTest::addColumn<QString>("filePath");
    QTest::addColumn<QString>("expected");

    QTest::newRow("no dot file w/o path") << u"file.abc"_s << u"file.abc"_s;
    QTest::newRow("no dot file w/ relative path") << u"folder/file"_s << u"folder/file"_s;
    QTest::newRow("no dot file w/ absolute path") << u"/folder/file"_s << u"/folder/file"_s;
    QTest::newRow("dot file w/o path") << u".hidden"_s << u"hidden"_s;
    QTest::newRow("dot file w/ relative path") << u"folder/.hidden"_s << u"folder/hidden"_s;
    QTest::newRow("dot file w/ absolute path") << u"/folder/.hidden"_s << u"/folder/hidden"_s;
    QTest::newRow("single dot as file name w/o path") << u"."_s << u"dot"_s;
    QTest::newRow("single dot as file name w/ relative path") << u"folder/."_s << u"folder/dot"_s;
    QTest::newRow("single dot as file name w/ absolute path") << u"/folder/."_s << u"/folder/dot"_s;
    QTest::newRow("multiple dots as file name w/o path") << u"..."_s << u"dots"_s;
    QTest::newRow("multiple dots as file name w/ relative path") << u"folder/..."_s << u"folder/dots"_s;
    QTest::newRow("multiple dots as file name w/ absolute path") << u"/folder/..."_s << u"/folder/dots"_s;
}

void PathHelperTest::testPrettifiedDotFileName()
{
    QFETCH(QString, filePath);
    QFETCH(QString, expected);

    QCOMPARE(Kleo::prettifiedDotFileName(filePath), expected);
}

QTEST_GUILESS_MAIN(PathHelperTest)
#include "pathhelpertest.moc"
