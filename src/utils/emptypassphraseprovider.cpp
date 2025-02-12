/*
    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2008 Klarälvdalens Datakonsult AB
    SPDX-FileCopyrightText: 2016, 2017 Bundesamt für Sicherheit in der Informationstechnik
    SPDX-FileContributor: Intevation GmbH

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include "emptypassphraseprovider.h"

#include <gpg-error.h>

char *EmptyPassphraseProvider::getPassphrase(const char *, const char *, bool, bool &)
{
    return gpgrt_strdup("");
}
