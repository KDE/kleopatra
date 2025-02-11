/*
    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2016 Bundesamt für Sicherheit in der Informationstechnik
    SPDX-FileContributor: Intevation GmbH

    SPDX-License-Identifier: GPL-2.0-or-later
*/
#include <config-kleopatra.h>

// Includes the real implementation

#if !HAVE_QDBUS && defined(_WIN32)
#include "kuniqueservice_win.cpp"
#elif HAVE_QDBUS
#include "kuniqueservice_dbus.cpp"
#else
#error "Uniqueservice is only implemented for DBus and Windows."
#endif

#include "moc_kuniqueservice.cpp"
