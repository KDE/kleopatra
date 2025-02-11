/*
    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2017 Bundesamt für Sicherheit in der Informationstechnik
    SPDX-FileContributor: Intevation GmbH

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#pragma once

#include <QDialog>
#include <QString>

namespace Kleo
{

/** Updatenotification for Gpg4win
 *
 * On Windows it is usual for Applications to notify the user
 * about updates. To avoid network access in Kleopatra and
 * to have only one TLS stack in our package this is implemented
 * in dirmngr.
 */
class UpdateNotification : public QDialog
{
public:
    /* Force an update check dirmngr loadswdb --force callse
     * check update afterwards. */
    static void forceUpdateCheck(QWidget *parent);
    /* Check for an update. The force parameter overrides the
     * NeverShow setting */
    static void checkUpdate(QWidget *parent, bool force = false);
    UpdateNotification(QWidget *parent, const QString &version);
};
} // namespace Kleo
