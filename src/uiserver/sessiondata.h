/* -*- mode: c++; c-basic-offset:4 -*-
    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2009 Klarälvdalens Datakonsult AB

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#pragma once

#include <QObject>

#include "assuancommand.h"

#include <QTimer>

#include <map>
#include <memory>

namespace Kleo
{

class SessionDataHandler;

class SessionData
{
public:
    std::map<QByteArray, std::shared_ptr<AssuanCommand::Memento>> mementos;

private:
    friend class ::Kleo::SessionDataHandler;
    SessionData();
    int ref;
    bool ripe;
};

class SessionDataHandler : public QObject
{
    Q_OBJECT
public:
    static std::shared_ptr<SessionDataHandler> instance();

    void enterSession(unsigned int id);
    void exitSession(unsigned int id);

    std::shared_ptr<SessionData> sessionData(unsigned int) const;

    void clear();

private Q_SLOTS:
    void slotCollectGarbage();

private:
    mutable std::map<unsigned int, std::shared_ptr<SessionData>> data;
    QTimer timer;

private:
    std::shared_ptr<SessionData> sessionDataInternal(unsigned int) const;
    SessionDataHandler();
};

}
