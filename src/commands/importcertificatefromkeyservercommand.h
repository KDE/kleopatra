/* -*- mode: c++; c-basic-offset:4 -*-
    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2022 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#pragma once

#include "importcertificatescommand.h"

namespace Kleo
{

class ImportCertificateFromKeyserverCommand : public ImportCertificatesCommand
{
    Q_OBJECT
public:
    explicit ImportCertificateFromKeyserverCommand(const QStringList &keyIds, const QString &id = {});
    ~ImportCertificateFromKeyserverCommand() override;

private:
    void doStart() override;

private:
    class Private;
    inline Private *d_func();
    inline const Private *d_func() const;
};
}
