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

QString Kleo::userFullName()
{
    const KEMailSettings e;
    auto name = e.getSetting(KEMailSettings::RealName);
#ifdef Q_OS_WIN
    if (name.isEmpty()) {
        name = win_get_user_name(NameDisplay);
    }
    if (name.isEmpty()) {
        name = win_get_user_name(NameUnknown);
    }
#endif
    if (name.isEmpty()) {
        name = env_get_user_name(UserInfoName);
    }
    return name;
}

QString Kleo::userEmailAddress()
{
    const KEMailSettings e;
    auto mbox = e.getSetting(KEMailSettings::EmailAddress);
#ifdef Q_OS_WIN
    if (mbox.isEmpty()) {
        mbox = win_get_user_name(NameUserPrincipal);
    }
#endif
    if (mbox.isEmpty()) {
        mbox = env_get_user_name(UserInfoEmailAddress);
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
