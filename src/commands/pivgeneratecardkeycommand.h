/*
    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2020 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/
#pragma once

#include "cardcommand.h"

namespace Kleo
{
namespace Commands
{

class PIVGenerateCardKeyCommand : public CardCommand
{
    Q_OBJECT
public:
    explicit PIVGenerateCardKeyCommand(const std::string &serialNumber, QWidget *parent);
    ~PIVGenerateCardKeyCommand() override;

    void setKeyRef(const std::string &keyref);

private:
    void doStart() override;
    void doCancel() override;

private:
    class Private;
    inline Private *d_func();
    inline const Private *d_func() const;
};

} // namespace Commands
} // namespace Kleo
