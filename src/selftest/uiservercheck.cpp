/* -*- mode: c++; c-basic-offset:4 -*-
    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2008 Klarälvdalens Datakonsult AB

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include <config-kleopatra.h>

#include "uiservercheck.h"

#include "implementation_p.h"
#include "selftest/testuiserver.h"

#include <QCoreApplication>
#include <QEventLoop>

#include <KLocalizedString>

using namespace Kleo;
using namespace Kleo::_detail;

namespace
{

class UiServerCheck : public SelfTestImplementation
{
public:
    explicit UiServerCheck()
        : SelfTestImplementation(i18nc("@title", "UiServer Connectivity"))
    {
        runTest();
    }

    void runTest()
    {
        TestUiServer command;

        {
            QEventLoop loop;
            loop.connect(&command, SIGNAL(finished()), SLOT(quit()));
            QMetaObject::invokeMethod(&command, "start", Qt::QueuedConnection);
            loop.exec();
        }

        if (command.error()) {
            m_passed = false;
            m_error = i18n("not reachable");
            m_explanation = xi18nc("@info", "Could not connect to UiServer: <message>%1</message>", command.errorString().toHtmlEscaped());
            m_proposedFix = xi18nc("@info",
                                   "<para>Check that your firewall is not set to block local connections "
                                   "(allow connections to <resource>localhost</resource> or <resource>127.0.0.1</resource>).</para>");
        } else if (command.serverPid() != QCoreApplication::applicationPid()) {
            m_passed = false;
            m_error = i18n("multiple instances");
            m_explanation = xi18nc("@info", "It seems another <application>Kleopatra</application> is running (with process-id %1)", command.serverPid());
            m_proposedFix = xi18nc("@info", "Quit any other running instances of <application>Kleopatra</application>.");
        } else {
            m_passed = true;
        }
    }
};
}

std::shared_ptr<SelfTest> Kleo::makeUiServerConnectivitySelfTest()
{
    return std::shared_ptr<SelfTest>(new UiServerCheck);
}
