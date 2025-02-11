/*
    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2007 Klarälvdalens Datakonsult AB
    SPDX-FileCopyrightText: 2020 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#pragma once

#include "command.h"

namespace Kleo
{

class CardCommand : public Command
{
    Q_OBJECT
public:
    explicit CardCommand(const std::string &serialNumber, QWidget *parent);
    ~CardCommand() override;

    void setAutoResetCardToOpenPGP(bool autoReset);
    bool autoResetCardToOpenPGP() const;

protected:
    class Private;
    inline Private *d_func();
    inline const Private *d_func() const;

protected:
    explicit CardCommand(Private *pp, QAbstractItemView *view = nullptr);
};

} // namespace Kleo
