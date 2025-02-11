/* -*- mode: c++; c-basic-offset:4 -*-
    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2008 Klarälvdalens Datakonsult AB
    SPDX-FileCopyrightText: 2016, 2017 Bundesamt für Sicherheit in der Informationstechnik
    SPDX-FileContributor: Intevation GmbH

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#pragma once

#include <gpgme++/interfaces/passphraseprovider.h>

class EmptyPassphraseProvider : public GpgME::PassphraseProvider
{
public:
    char *getPassphrase(const char *useridHint, const char *description, bool previousWasBad, bool &canceled) override;
};
