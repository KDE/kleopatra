/* -*- mode: c++; c-basic-offset:4 -*-
    commands/changeroottrustcommand.h

    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2010 Klarälvdalens Datakonsult AB

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#pragma once

#include <commands/command.h>

#include <gpgme++/key.h>

namespace Kleo
{
namespace Commands
{

class ChangeRootTrustCommand : public Command
{
    Q_OBJECT
protected:
    ChangeRootTrustCommand(GpgME::Key::OwnerTrust trust, QAbstractItemView *view, KeyListController *parent);

public:
    ~ChangeRootTrustCommand() override;

    /* reimp */ static Restrictions restrictions()
    {
        return OnlyOneKey | MustBeCMS | MustBeRoot;
    }

private:
    void doStart() override;
    void doCancel() override;

private:
    class Private;
    inline Private *d_func();
    inline const Private *d_func() const;
};

class TrustRootCommand : public ChangeRootTrustCommand
{
public:
    TrustRootCommand(QAbstractItemView *view, KeyListController *parent)
        : ChangeRootTrustCommand(GpgME::Key::Ultimate, view, parent)
    {
    }

    /* reimp */ static Restrictions restrictions()
    {
        return ChangeRootTrustCommand::restrictions() | MustBeUntrustedRoot;
    }
};

class DistrustRootCommand : public ChangeRootTrustCommand
{
public:
    DistrustRootCommand(QAbstractItemView *view, KeyListController *parent)
        : ChangeRootTrustCommand(GpgME::Key::Never, view, parent)
    {
    }

    /* reimp */ static Restrictions restrictions()
    {
        return ChangeRootTrustCommand::restrictions() | MustBeTrustedRoot;
    }
};

}
}
