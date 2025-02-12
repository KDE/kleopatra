/*
    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2007 Klarälvdalens Datakonsult AB

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#pragma once

#include <QObject>

#include <cstdio>
#include <memory>

class QString;

namespace Kleo
{

class AssuanCommandFactory;

class UiServer : public QObject
{
    Q_OBJECT
public:
    explicit UiServer(const QString &socket, QObject *parent = nullptr);
    ~UiServer() override;

    static void setLogStream(FILE *file);

    bool registerCommandFactory(const std::shared_ptr<AssuanCommandFactory> &cmdFactory);

    bool waitForStopped(unsigned int ms = 0xFFFFFFFF);

    bool isStopped() const;
    bool isStopping() const;

    QString socketName() const;

public Q_SLOTS:
    void start();
    void stop();
    void enableCryptoCommands(bool enable = true);

Q_SIGNALS:
    void stopped();
    void startKeyManagerRequested();
    void startConfigDialogRequested();

private:
    class Private;
    const std::unique_ptr<Private> d;
};

}
