/* -*- mode: c++; c-basic-offset:4 -*-
    core/command.h

    This file is part of KleopatraClient, the Kleopatra interface library
    SPDX-FileCopyrightText: 2008 Klarälvdalens Datakonsult AB

    SPDX-License-Identifier: LGPL-2.0-or-later
*/

#pragma once

#include <QObject>

class QString;

namespace Kleo
{
namespace Commands
{

class TestUiServerCommand : public QObject
{
    Q_OBJECT
public:
    explicit TestUiServerCommand(QObject *parent = nullptr);
    ~TestUiServerCommand() override;

    bool error() const;
    QString errorString() const;
    qint64 serverPid() const;

public Q_SLOTS:
    void start();

Q_SIGNALS:
    void started();
    void finished();

protected:
    class Private;
    Private *d;
};

}
}
