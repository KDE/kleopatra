/*
    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2022 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#pragma once

#include "kleoconfigmodule.h"

#include <QWidget>
#include <memory>

namespace Kleo
{
namespace Config
{

class SmartCardConfigurationPage : public KleoConfigModule
{
    Q_OBJECT
public:
    explicit SmartCardConfigurationPage(QWidget *parent);
    ~SmartCardConfigurationPage() override;

    void load() override;
    void save() override;
    void defaults() override;

private:
    class Private;
    std::unique_ptr<Private> d;
};

}
}
