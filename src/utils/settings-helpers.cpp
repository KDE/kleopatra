/*
    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2026 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include "settings-helpers.h"

#include "userinfo.h"

#include <settings.h>

using namespace Qt::StringLiterals;

QString cnForNewCertificates()
{
    QString result;
    const auto settings = Kleo::Settings{};
    // prefer explicitly configured name over the values retrieved from the system
    result = settings.name();
    if (result.isEmpty() && settings.prefillCN()) {
        result = Kleo::userFullName(settings.prefillSourcesCN());
    }
    return result;
}

QString emailForNewCertificates()
{
    QString result;
    const auto settings = Kleo::Settings{};
    // prefer explicitly configured email over the values retrieved from the system
    result = settings.email();
    if (result.isEmpty() && settings.prefillEmail()) {
        result = Kleo::userEmailAddress(settings.prefillSourcesEmail());
    }
    return result;
}

QString nameForNewCertificates()
{
    QString result;
    const auto settings = Kleo::Settings{};
    // prefer explicitly configured name over the values retrieved from the system
    result = settings.name();
    if (result.isEmpty() && settings.prefillName()) {
        result = Kleo::userFullName(settings.prefillSourcesName());
    }
    return result;
}
