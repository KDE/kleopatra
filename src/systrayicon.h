/* -*- mode: c++; c-basic-offset:4 -*-
    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2007 Klarälvdalens Datakonsult AB

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#pragma once

#include <utils/systemtrayicon.h>
#ifndef QT_NO_SYSTEMTRAYICON

#include <memory>

class MainWindow;
class QDialog;

class SysTrayIcon : public Kleo::SystemTrayIcon
{
    Q_OBJECT
public:
    explicit SysTrayIcon(QObject *parent = nullptr);
    ~SysTrayIcon() override;

    MainWindow *mainWindow() const;
    QDialog *attentionWindow() const;

public Q_SLOTS:
    void setFirstCardWithNullPin(const std::string &serialNumber);

private:
    void doActivated() override;
    void slotEnableDisableActions() override;

private:
    class Private;
    const std::unique_ptr<Private> d;
    Q_PRIVATE_SLOT(d, void slotAbout())
    Q_PRIVATE_SLOT(d, void slotSetInitialPin())
};

#endif // QT_NO_SYSTEMTRAYICON
