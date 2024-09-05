/*
    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2024 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/
#pragma once

#include <QHash>
#include <QObject>

/**
 * Helper for status messages with optional context.
 *
 * Status messages without context (global messages) take precedence over
 * messages with context. The latter are shown if their context is active.
 */
class StatusMessage : public QObject
{
    Q_OBJECT
public:
    explicit StatusMessage(QObject *parent = nullptr);
    ~StatusMessage() override;

public Q_SLOTS:
    void clearMessage(const QByteArray &context = {});
    void showMessage(const QString &message, const QByteArray &context = {});

    void clearContext();
    void setContext(const QByteArray &context);

Q_SIGNALS:
    void messageChanged(const QString &message);

private:
    void updateMessage();
    void emitMessage(const QString &message);

private:
    QString mLastMessage;
    QByteArray mContext;
    QHash<QByteArray, QString> mMessages;
};
