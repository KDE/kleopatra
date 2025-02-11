/*
    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2016 Bundesamt für Sicherheit in der Informationstechnik
    SPDX-FileContributor: Intevation GmbH

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include "kuniqueservice.h"
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

KUniqueService::KUniqueService()
    : d_ptr(new KUniqueServicePrivate(this))
{
}

KUniqueService::~KUniqueService()
{
    delete d_ptr;
}

void KUniqueService::setExitValue(int code)
{
    Q_D(KUniqueService);
    d->setExitValue(code);
}
