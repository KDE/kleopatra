/*
    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2008 Klarälvdalens Datakonsult AB

    SPDX-License-Identifier: GPL-2.0-or-later
*/
#pragma once

#include "kleoconfigmodule.h"

#include <QWidget>

namespace Kleo
{
namespace Config
{

class SMimeValidationConfigurationWidget;

class SMimeValidationConfigurationPage : public KleoConfigModule
{
    Q_OBJECT
public:
    explicit SMimeValidationConfigurationPage(QWidget *parent);

    void load() override;
    void save() override;
    void defaults() override;

private:
    SMimeValidationConfigurationWidget *mWidget = nullptr;
};

}
}
