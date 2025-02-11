/*
    This file is part of Kleopatra
    SPDX-FileCopyrightText: 2000 Espen Sand <espen@kde.org>
    SPDX-FileCopyrightText: 2001-2002 Marc Mutz <mutz@kde.org>
    SPDX-FileCopyrightText: 2004 Klarälvdalens Datakonsult AB

    SPDX-FileCopyrightText: 2016 Bundesamt für Sicherheit in der Informationstechnik
    SPDX-FileContributor: Intevation GmbH

    SPDX-License-Identifier: GPL-2.0-only
*/

#pragma once

#include <config-kleopatra.h>

#include "kleopageconfigdialog.h"

class ConfigureDialog : public KleoPageConfigDialog
{
    Q_OBJECT
public:
    explicit ConfigureDialog(QWidget *parent = nullptr);

protected:
    void hideEvent(QHideEvent *) override;
};
