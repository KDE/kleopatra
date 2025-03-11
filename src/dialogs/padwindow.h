// SPDX-FileCopyrightText: 2025 g10 Code GmbH
// SPDX-FileContributor: Tobias Fella <tobias.fella@gnupg.com>
// SPDX-License-Identifier: GPL-2.0-or-later

#pragma once

#include <QMainWindow>

#include <memory>

class PadWindow : public QMainWindow
{
    Q_OBJECT
public:
    explicit PadWindow(QWidget *parent = nullptr);
    ~PadWindow() override;

private:
    class Private;
    const std::unique_ptr<Private> d;
};
