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

static QStringList prefillCN(const Kleo::Settings &settings)
{
    const QStringList prefillCNValue = settings.prefillCN();
    if (prefillCNValue.size() == 1) {
        if (prefillCNValue.front() == "true"_L1) {
            return settings.defaultPrefillCNValue();
        } else if (prefillCNValue.front() == "false"_L1) {
            return {};
        }
    }
    return prefillCNValue;
}

static QStringList prefillEmail(const Kleo::Settings &settings)
{
    const QStringList prefillEmailValue = settings.prefillEmail();
    if (prefillEmailValue.size() == 1) {
        if (prefillEmailValue.front() == "true"_L1) {
            return settings.defaultPrefillEmailValue();
        } else if (prefillEmailValue.front() == "false"_L1) {
            return {};
        }
    }
    return prefillEmailValue;
}

static QStringList prefillName(const Kleo::Settings &settings)
{
    const QStringList prefillNameValue = settings.prefillName();
    if (prefillNameValue.size() == 1) {
        if (prefillNameValue.front() == "true"_L1) {
            return settings.defaultPrefillNameValue();
        } else if (prefillNameValue.front() == "false"_L1) {
            return {};
        }
    }
    return prefillNameValue;
}

QString cnForNewCertificates()
{
    QString result;
    const auto settings = Kleo::Settings{};
    // prefer explicitly configured name over the values retrieved from the system
    result = settings.name();
    if (result.isEmpty()) {
        const QStringList prefillCNValue = prefillCN(settings);
        if (!prefillCNValue.empty()) {
            result = Kleo::userFullName(prefillCNValue);
        }
    }
    return result;
}

QString emailForNewCertificates()
{
    QString result;
    const auto settings = Kleo::Settings{};
    // prefer explicitly configured email over the values retrieved from the system
    result = settings.email();
    if (result.isEmpty()) {
        const QStringList prefillEmailValue = prefillEmail(settings);
        if (!prefillEmailValue.empty()) {
            result = Kleo::userEmailAddress(prefillEmailValue);
        }
    }
    return result;
}

QString nameForNewCertificates()
{
    QString result;
    const auto settings = Kleo::Settings{};
    // prefer explicitly configured name over the values retrieved from the system
    result = settings.name();
    if (result.isEmpty()) {
        const QStringList prefillNameValue = prefillName(settings);
        if (!prefillNameValue.empty()) {
            result = Kleo::userFullName(prefillNameValue);
        }
    }
    return result;
}
