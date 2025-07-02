/*
    kuniqueservice_dbus.cpp

    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2016 Bundesamt für Sicherheit in der Informationstechnik
    SPDX-FileContributor: Intevation GmbH

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include "kuniqueservice.h"

#include <kleopatra_debug.h>

#include <KDBusService>

class KUniqueService::KUniqueServicePrivate
{
    Q_DISABLE_COPY(KUniqueServicePrivate)

public:
    KUniqueServicePrivate(KUniqueService *q)
        : mService(KDBusService::Unique)
    {
        QObject::connect(&mService, &KDBusService::activateRequested, q, &KUniqueService::activateRequested);
    }

    void setExitValue(int code)
    {
        mService.setExitValue(code);
    }

private:
    KDBusService mService;
};

KUniqueService::KUniqueService(QObject *parent)
    : QObject(parent)
    , d_ptr(new KUniqueServicePrivate(this))
{
}

KUniqueService::~KUniqueService()
{
    qCDebug(KLEOPATRA_LOG) << __func__;
    delete d_ptr;
}

void KUniqueService::setExitValue(int code)
{
    Q_D(KUniqueService);
    d->setExitValue(code);
}
