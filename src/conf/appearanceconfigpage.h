/* -*- mode: c++; c-basic-offset:4 -*-
    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2004, 2008 Klarälvdalens Datakonsult AB

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#pragma once

#include "kleoconfigmodule.h"

#include <QWidget>

namespace Kleo
{
namespace Config
{

class AppearanceConfigWidget;

/**
 * "Appearance" configuration page for kleopatra's configuration dialog
 */
class AppearanceConfigurationPage : public KleoConfigModule
{
    Q_OBJECT
public:
    explicit AppearanceConfigurationPage(QWidget *parent);

    void load() override;
    void save() override;
    void defaults() override;

private:
    AppearanceConfigWidget *mWidget = nullptr;
};

}
}
