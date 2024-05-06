/* -*- mode: c++; c-basic-offset:4 -*-
    conf/cryptooperationsconfigpage.h

    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2010 Klarälvdalens Datakonsult AB

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#pragma once

#include <QWidget>

#include "kleoconfigmodule.h"

namespace Kleo
{
namespace Config
{

class CryptoOperationsConfigWidget;

/**
 * "Crypto Operations" configuration page for kleopatra's configuration dialog
 */
class CryptoOperationsConfigurationPage : public KleoConfigModule
{
    Q_OBJECT
public:
    explicit CryptoOperationsConfigurationPage(QWidget *parent);

public Q_SLOTS:
    void load() override;
    void save() override;
    void defaults() override;

private:
    CryptoOperationsConfigWidget *mWidget;
};

}
}
