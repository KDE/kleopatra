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

#if __has_include(<QGpgME/ADQueryJob>)
#define HAVE_AD_QUERY_JOB
#include "memory-helpers.h"

#include <QGpgME/ADQueryJob>
#include <QGpgME/ADQueryResult>
#include <QGpgME/Debug>
#include <QGpgME/Protocol>
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

static QString query_active_directory([[maybe_unused]] const QString &attributeName)
{
#ifdef Q_OS_WIN
#ifdef HAVE_AD_QUERY_JOB
    const QString userPrincipalName = win_get_user_name(NameUserPrincipal);
    if (userPrincipalName.isEmpty()) {
        qCDebug(KLEOPATRA_LOG) << __func__ << "Failed to get NameUserPrincipal for querying AD";
        return {};
    }

    auto job = wrap_unique(QGpgME::openpgp()->adQueryJob());
    const QString filter = u"(&(objectcategory=person)(objectclass=user)(userPrincipalName=%1))"_s.arg(userPrincipalName);
    const QGpgME::ADQueryResult result = job->exec(filter, {attributeName}, QGpgME::ADQueryOption::SubstituteVariables);
    if (result.error()) {
        qCDebug(KLEOPATRA_LOG) << __func__ << "AD query failed:" << result.error();
    } else {
        for (const auto &attribute : result.attributes()) {
            if (attribute.name == attributeName) {
                return attribute.value;
            }
        }
    }
#else
    qCDebug(KLEOPATRA_LOG) << __func__ << "QGpgME does not support AD queries";
#endif
#endif
    return {};
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
        } else if (sourceLower == "addisplayname"_L1) {
            name = query_active_directory(u"displayName"_s);
        } else if (sourceLower == "adfirstnamelastname"_L1) {
            const QString firstName = query_active_directory(u"givenName"_s);
            const QString lastName = query_active_directory(u"sn"_s);
            if (!firstName.isEmpty() && !lastName.isEmpty()) {
                name = firstName + u' ' + lastName;
            }
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
        } else if (sourceLower == "admail"_L1) {
            mbox = query_active_directory(u"mail"_s);
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
