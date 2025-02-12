/*
    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2020 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#pragma once

#include "command.h"

#include <gpgme++/key.h>

namespace Kleo
{
namespace Commands
{

class RevokeCertificationCommand : public Command
{
    Q_OBJECT
public:
    RevokeCertificationCommand(QAbstractItemView *view, KeyListController *parent);
    explicit RevokeCertificationCommand(const GpgME::Key &key);
    explicit RevokeCertificationCommand(const GpgME::UserID &uid);
    explicit RevokeCertificationCommand(const std::vector<GpgME::UserID> &uids);
    explicit RevokeCertificationCommand(const GpgME::UserID::Signature &signature);
    ~RevokeCertificationCommand() override;

    /* reimp */ static Restrictions restrictions()
    {
        return OnlyOneKey | MustBeOpenPGP;
    }

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
