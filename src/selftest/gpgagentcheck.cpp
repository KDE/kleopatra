/* -*- mode: c++; c-basic-offset:4 -*-
    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2009 Klarälvdalens Datakonsult AB

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include <config-kleopatra.h>

#include "gpgagentcheck.h"

#include "implementation_p.h"

#include <Libkleo/Formatting>

#include <gpgme++/context.h>

#include <KLocalizedString>

using namespace Kleo;
using namespace Kleo::_detail;
using namespace GpgME;

namespace
{

class GpgAgentCheck : public SelfTestImplementation
{
public:
    explicit GpgAgentCheck()
        : SelfTestImplementation(i18nc("@title", "Gpg-Agent Connectivity"))
    {
        runTest();
    }

    void runTest()
    {
        m_skipped = true;

        if (!hasFeature(AssuanEngineFeature, 0)) {
            m_error = i18n("GpgME library too old");
            m_explanation = i18nc("@info",
                                  "Either the GpgME library itself is too old, "
                                  "or the GpgME++ library was compiled against "
                                  "an older GpgME that did not support connecting to gpg-agent.");
            m_proposedFix = xi18nc("@info",
                                   "Upgrade to <application>gpgme</application> 1.2.0 or higher, "
                                   "and ensure that gpgme++ was compiled against it.");
        } else if (ensureEngineVersion(GpgME::GpgConfEngine, 2, 1, 0)) {
            // 2.1 starts the agent on demand and requires it. So for 2.1.0 we can assume
            // autostart works and we don't need to care about the agent.
            m_skipped = false;
            m_passed = true;
            return;
        } else {
            Error error;
            const std::unique_ptr<Context> ctx = Context::createForEngine(AssuanEngine, &error);
            if (!ctx.get()) {
                m_error = i18n("GpgME does not support gpg-agent");
                m_explanation = xi18nc("@info",
                                       "<para>The <application>GpgME</application> library is new "
                                       "enough to support <application>gpg-agent</application>, "
                                       "but does not seem to do so in this installation.</para>"
                                       "<para>The error returned was: <message>%1</message>.</para>",
                                       Formatting::errorAsString(error).toHtmlEscaped());
                // PENDING(marc) proposed fix?
            } else {
                m_skipped = false;

                const Error error = ctx->assuanTransact("GETINFO version");
                if (error) {
                    m_passed = false;
                    m_error = i18n("unexpected error");
                    m_explanation = xi18nc("@info",
                                           "<para>Unexpected error while asking <application>gpg-agent</application> "
                                           "for its version.</para>"
                                           "<para>The error returned was: <message>%1</message>.</para>",
                                           Formatting::errorAsString(error).toHtmlEscaped());
                    // PENDING(marc) proposed fix?
                } else {
                    m_passed = true;
                }
            }
        }
    }
};
}

std::shared_ptr<SelfTest> Kleo::makeGpgAgentConnectivitySelfTest()
{
    return std::shared_ptr<SelfTest>(new GpgAgentCheck);
}
