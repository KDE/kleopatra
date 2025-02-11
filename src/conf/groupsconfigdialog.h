/*
    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2021 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#pragma once

#include <QDialog>

#include <memory>

class GroupsConfigDialog : public QDialog
{
    Q_OBJECT
public:
    explicit GroupsConfigDialog(QWidget *parent = nullptr);
    ~GroupsConfigDialog() override;

private:
    class Private;
    const std::unique_ptr<Private> d;
};
