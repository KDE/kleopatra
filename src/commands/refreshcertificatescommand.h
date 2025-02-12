/*
    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2022 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#pragma once

#include "command.h"

namespace Kleo
{
class RefreshCertificatesCommand : public Command
{
    Q_OBJECT
public:
    explicit RefreshCertificatesCommand(QAbstractItemView *view, KeyListController *parent);
    explicit RefreshCertificatesCommand(const GpgME::Key &key);
    ~RefreshCertificatesCommand() override;

    /* reimp */ static Restrictions restrictions()
    {
        return NeedSelection;
    }

private:
    void doStart() override;
    void doCancel() override;

private:
    class Private;
    inline Private *d_func();
    inline const Private *d_func() const;
};
}
