/*
    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2021 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include "userinfo.h"

// Needed for global defines
#include <QtSystemDetection>

#ifdef Q_OS_WIN
#include "userinfo_win_p.h"
#endif

#include <KEMailSettings>
#include <KEmailAddress>

#include <kleopatra_debug.h>

using namespace Qt::StringLiterals;

namespace
{
enum UserInfoDetail {
    UserInfoName,
    UserInfoEmailAddress,
};

static QString env_get_user_name(UserInfoDetail detail)
{
    const auto var = qEnvironmentVariable("EMAIL");
    if (!var.isEmpty()) {
        QString name, addrspec, comment;
        const auto result = KEmailAddress::splitAddress(var, name, addrspec, comment);
        if (result == KEmailAddress::AddressOk) {
            return (detail == UserInfoEmailAddress ? addrspec : name);
        }
    }
    return QString();
}
}

QString Kleo::userFullName(const QStringList &sources)
{
    QString name;
    for (const auto &source : sources) {
        const QString sourceLower = source.toLower();
        if (sourceLower == "kemailsettings"_L1) {
            name = KEMailSettings().getSetting(KEMailSettings::RealName);
        } else if (sourceLower == "wingetusername"_L1) {
#ifdef Q_OS_WIN
            name = win_get_user_name(NameDisplay);
            if (name.isEmpty()) {
                name = win_get_user_name(NameUnknown);
            }
#endif
        } else if (sourceLower == "envemail"_L1) {
            name = env_get_user_name(UserInfoName);
        } else {
            qCDebug(KLEOPATRA_LOG) << __func__ << "Unknown/unsupported source" << source;
        }
        if (!name.isEmpty()) {
            qCDebug(KLEOPATRA_LOG) << __func__ << "Using name from source" << source;
            break;
        }
    }
    return name;
}

QString Kleo::userEmailAddress(const QStringList &sources)
{
    QString mbox;
    for (const auto &source : sources) {
        const QString sourceLower = source.toLower();
        if (sourceLower == "kemailsettings"_L1) {
            mbox = KEMailSettings().getSetting(KEMailSettings::EmailAddress);
        } else if (sourceLower == "wingetusername"_L1) {
#ifdef Q_OS_WIN
            mbox = win_get_user_name(NameUserPrincipal);
#endif
        } else if (sourceLower == "envemail"_L1) {
            mbox = env_get_user_name(UserInfoEmailAddress);
        } else {
            qCDebug(KLEOPATRA_LOG) << __func__ << "Unknown/unsupported source" << source;
        }
        if (!mbox.isEmpty()) {
            qCDebug(KLEOPATRA_LOG) << __func__ << "Using email from source" << source;
            break;
        }
    }
    return mbox;
}

bool Kleo::userIsElevated()
{
#ifdef Q_OS_WIN
    static bool ret = win_user_is_elevated();
    return ret;
#else
    return false;
#endif
}
