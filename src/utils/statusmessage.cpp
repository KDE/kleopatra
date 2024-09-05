/*
    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2024 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include "statusmessage.h"

StatusMessage::StatusMessage(QObject *parent)
    : QObject{parent}
{
}

StatusMessage::~StatusMessage() = default;

void StatusMessage::clearMessage(const QByteArray &context)
{
    mMessages[context].clear();
    updateMessage();
}

void StatusMessage::showMessage(const QString &message, const QByteArray &context)
{
    mMessages[context] = message;
    updateMessage();
}

void StatusMessage::clearContext()
{
    mContext.clear();
    updateMessage();
}

void StatusMessage::setContext(const QByteArray &context)
{
    mContext = context;
    updateMessage();
}

void StatusMessage::updateMessage()
{
    static const QByteArray globalContext{};

    const QString &globalMessage = mMessages[globalContext];
    if (!globalMessage.isEmpty() || mContext.isEmpty()) {
        emitMessage(globalMessage);
    } else {
        const QString &contextMessage = mMessages[mContext];
        if (!contextMessage.isEmpty()) {
            emitMessage(contextMessage);
        } else {
            emitMessage({});
        }
    }
}

void StatusMessage::emitMessage(const QString &message)
{
    if (message != mLastMessage) {
        mLastMessage = message;
        Q_EMIT messageChanged(message);
    }
}
