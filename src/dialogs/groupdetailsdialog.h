/*
    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2021 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#pragma once

#include <QDialog>

#include <memory>

namespace Kleo
{
class KeyGroup;

namespace Dialogs
{

class GroupDetailsDialog : public QDialog
{
    Q_OBJECT
public:
    explicit GroupDetailsDialog(QWidget *parent = nullptr);
    ~GroupDetailsDialog() override;

    void setGroup(const Kleo::KeyGroup &group);

private:
    class Private;
    const std::unique_ptr<Private> d;
};

}
}
