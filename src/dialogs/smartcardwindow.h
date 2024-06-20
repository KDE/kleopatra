/*
    dialogs/smartcardwindow.h

    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2024 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/
#pragma once

#include <QMainWindow>

#include <memory>

class SmartCardWindow : public QMainWindow
{
    Q_OBJECT
public:
    explicit SmartCardWindow(QWidget *parent = nullptr);
    ~SmartCardWindow() override;

private:
    class Private;
    const std::unique_ptr<Private> d;
};
