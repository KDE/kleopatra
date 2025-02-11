/* -*- mode: c++; c-basic-offset:4 -*-
    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2018 Intevation GmbH

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#pragma once

#include "importcertificatescommand.h"

#include <gpgme++/global.h>

namespace Kleo
{

class ImportCertificateFromDataCommand : public ImportCertificatesCommand
{
    Q_OBJECT
public:
    explicit ImportCertificateFromDataCommand(const QByteArray &data, GpgME::Protocol proto, const QString &id = QString());
    ~ImportCertificateFromDataCommand() override;

private:
    void doStart() override;

private:
    class Private;
    inline Private *d_func();
    inline const Private *d_func() const;
};
}
