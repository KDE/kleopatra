/* -*- mode: c++; c-basic-offset:4 -*-
    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2010 Klarälvdalens Datakonsult AB

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include <config-kleopatra.h>

#include "libkleopatrarccheck.h"

#include "implementation_p.h"

#include <utils/archivedefinition.h>

#include <Libkleo/ChecksumDefinition>

#include <KLocalizedString>

using namespace Kleo;
using namespace Kleo::_detail;

namespace
{

class LibKleopatraRcCheck : public SelfTestImplementation
{
public:
    explicit LibKleopatraRcCheck()
        : SelfTestImplementation(i18nc("@title", "Config File 'libkleopatrarc'"))
    {
        runTest();
    }

    void runTest()
    {
        QStringList errors;
        ArchiveDefinition::getArchiveDefinitions(errors);
        ChecksumDefinition::getChecksumDefinitions(errors);

        m_passed = errors.empty();
        if (m_passed) {
            return;
        }
        m_error = i18n("Errors found");

        // The building of the following string is a bit of a hack to avoid
        // that xi18nc does not escape the html tags while not breaking
        // the historic string.
        m_explanation = xi18nc("@info",
                               "<para>Kleopatra detected the following errors in the libkleopatrarc configuration:</para>"
                               "%1",
                               QStringLiteral("%1"))
                            .arg(QStringLiteral("<ol><li>") + errors.join(QLatin1StringView("</li><li>")) + QStringLiteral("</li></ol>"));
    }

    ///* reimp */ bool canFixAutomatically() const { return false; }
};
}

std::shared_ptr<SelfTest> Kleo::makeLibKleopatraRcSelfTest()
{
    return std::shared_ptr<SelfTest>(new LibKleopatraRcCheck);
}
