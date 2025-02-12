/*
    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2020 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#pragma once

#include <commands/cardcommand.h>

namespace Kleo
{
namespace Commands
{

class CreateOpenPGPKeyFromCardKeysCommand : public CardCommand
{
    Q_OBJECT
public:
    explicit CreateOpenPGPKeyFromCardKeysCommand(const std::string &serialNumber, const std::string &appName, QWidget *parent = nullptr);
    ~CreateOpenPGPKeyFromCardKeysCommand() override;

    static bool isSupported();

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
