/*
    SPDX-FileCopyrightText: 2024 g10 Code GmbH
    SPDX-FileContributor: Tobias Fella <tobias.fella@gnupg.com>

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#pragma once

#include <commands/command.h>

namespace Kleo
{
namespace Commands
{

class AddADSKCommand : public Command
{
    Q_OBJECT
public:
    explicit AddADSKCommand(const GpgME::Key &key);
    ~AddADSKCommand() override;

private:
    void doStart() override;
    void doCancel() override;

    class Private;
    inline Private *d_func();
    inline const Private *d_func() const;
};

}
}
