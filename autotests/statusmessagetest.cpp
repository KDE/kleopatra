/*
    This file is part of Kleopatra's test suite.
    SPDX-FileCopyrightText: 2024 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include <utils/statusmessage.h>

#include <QDebug>
#include <QSignalSpy>
#include <QTest>

using namespace Qt::Literals::StringLiterals;

class StatusMessageTest : public QObject
{
    Q_OBJECT

private Q_SLOTS:
    void testStatusMessage();
    void testStatusMessageWithContext();
};

void StatusMessageTest::testStatusMessage()
{
    StatusMessage statusMessage;

    QSignalSpy spy{&statusMessage, &StatusMessage::messageChanged};
    QVERIFY(spy.isValid());

    statusMessage.showMessage(u"Hello"_s);
    QVERIFY(!spy.empty());
    QCOMPARE(spy.last().value(0).toString(), u"Hello"_s);

    statusMessage.showMessage(u"World"_s);
    QCOMPARE(spy.last().value(0).toString(), u"World"_s);

    statusMessage.clearMessage();
    QVERIFY(spy.last().value(0).toString().isEmpty());
}

void StatusMessageTest::testStatusMessageWithContext()
{
    StatusMessage statusMessage;

    QSignalSpy spy{&statusMessage, &StatusMessage::messageChanged};
    QVERIFY(spy.isValid());

    const QByteArray venus{"venus"};
    const QByteArray mars{"mars"};

    // message with context is shown if context is active or when it becomes active
    statusMessage.showMessage(u"Hello Venus"_s, venus);
    QVERIFY(spy.empty());
    statusMessage.setContext(venus);
    QVERIFY(!spy.empty());
    QCOMPARE(spy.last().value(0).toString(), u"Hello Venus"_s);

    // message without context takes precedence over messages with context
    statusMessage.showMessage(u"Hello Solar System"_s);
    QCOMPARE(spy.last().value(0).toString(), u"Hello Solar System"_s);
    statusMessage.showMessage(u"Hello Mars"_s, mars);
    QCOMPARE(spy.last().value(0).toString(), u"Hello Solar System"_s);
    statusMessage.setContext(mars);
    QCOMPARE(spy.last().value(0).toString(), u"Hello Solar System"_s);
    statusMessage.clearMessage();
    QCOMPARE(spy.last().value(0).toString(), u"Hello Mars"_s);

    statusMessage.setContext(venus);
    QCOMPARE(spy.last().value(0).toString(), u"Hello Venus"_s);
    statusMessage.showMessage(u"Hello Venus again"_s, venus);
    QCOMPARE(spy.last().value(0).toString(), u"Hello Venus again"_s);
    statusMessage.clearMessage(venus);
    QVERIFY(spy.last().value(0).toString().isEmpty());
    statusMessage.setContext(mars);
    QCOMPARE(spy.last().value(0).toString(), u"Hello Mars"_s);
    statusMessage.clearContext();
    QVERIFY(spy.last().value(0).toString().isEmpty());
}

QTEST_MAIN(StatusMessageTest)
#include "statusmessagetest.moc"
