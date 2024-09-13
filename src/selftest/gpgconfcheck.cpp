/* -*- mode: c++; c-basic-offset:4 -*-
    selftest/gpgconfcheck.cpp

    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2008 Klarälvdalens Datakonsult AB

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include <config-kleopatra.h>

#include "gpgconfcheck.h"

#include "implementation_p.h"

#include <Libkleo/GnuPG>
#include <Libkleo/Hex>

#include "kleopatra_debug.h"
#include <KLocalizedString>

#include <QGpgME/CryptoConfig>
#include <QGpgME/Protocol>

using namespace Kleo;
using namespace Kleo::_detail;

namespace
{

class GpgConfCheck : public SelfTestImplementation
{
    QString m_component;

public:
    explicit GpgConfCheck(const char *component)
        : SelfTestImplementation(
              i18nc("@title", "%1 Configuration Check", component && *component ? QLatin1StringView(component) : QLatin1StringView("gpgconf")))
        , m_component(QLatin1StringView(component))
    {
        runTest();
    }

    void runTest()
    {
        const auto conf = QGpgME::cryptoConfig();
        QString message;
        m_passed = true;

        if (!conf) {
            message = QStringLiteral("Could not be started.");
            m_passed = false;
        } else if (m_component.isEmpty() && conf->componentList().empty()) {
            message = QStringLiteral("Could not list components.");
            m_passed = false;
        } else if (!m_component.isEmpty()) {
            const auto comp = conf->component(m_component);
            if (!comp) {
                message = QStringLiteral("Binary could not be found.");
                m_passed = false;
            } else if (comp->groupList().empty()) {
                // If we don't have any group it means that list-options
                // for this component failed.
                message = QStringLiteral("The configuration file is invalid.");
                m_passed = false;
            }
        }

        if (!m_passed) {
            m_error = i18nc("self-test did not pass", "Failed");
            m_explanation = i18n(
                "There was an error executing the GnuPG configuration self-check for %2:\n"
                "  %1\n"
                "You might want to execute \"gpgconf %3\" on the command line.\n",
                message,
                m_component.isEmpty() ? QStringLiteral("GnuPG") : m_component,
                QStringLiteral("--check-options ") + (m_component.isEmpty() ? QString() : m_component));

            // To avoid modifying the l10n
            m_explanation.replace(QLatin1Char('\n'), QStringLiteral("<br/>"));
        }
    }
};
}

std::shared_ptr<SelfTest> Kleo::makeGpgConfCheckConfigurationSelfTest(const char *component)
{
    return std::shared_ptr<SelfTest>(new GpgConfCheck(component));
}
