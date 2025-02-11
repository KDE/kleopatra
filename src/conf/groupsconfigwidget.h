/*
    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2021 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#pragma once

#include <QWidget>

#include <memory>
#include <vector>

namespace Kleo
{
class KeyGroup;

class GroupsConfigWidget : public QWidget
{
    Q_OBJECT
public:
    explicit GroupsConfigWidget(QWidget *parent = nullptr);
    ~GroupsConfigWidget() override;

    void setGroups(const std::vector<KeyGroup> &groups);
    std::vector<KeyGroup> groups() const;

Q_SIGNALS:
    void changed();

private:
    class Private;
    const std::unique_ptr<Private> d;
};

}
