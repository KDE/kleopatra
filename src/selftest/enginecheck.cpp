/* -*- mode: c++; c-basic-offset:4 -*-
    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2008 Klarälvdalens Datakonsult AB

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include <config-kleopatra.h>

#include "enginecheck.h"
#include <Libkleo/GnuPG>

#include "implementation_p.h"

#include <gpgme++/engineinfo.h>
#include <gpgme++/error.h>
#include <gpgme++/global.h>

#include <gpg-error.h>

#include "kleopatra_debug.h"
#include <KLocalizedString>

#include <QGpgME/CryptoConfig>
#include <QGpgME/Protocol>

#include <QFile>

#include <algorithm>

using namespace Kleo;
using namespace Kleo::_detail;
using namespace GpgME;

static QString engine_name(GpgME::Engine eng)
{
    static const char *engines[] = {"gpg", "gpgsm", "gpgconf"};
    return QString::fromLatin1(engines[eng]);
}

static QString test_name(GpgME::Engine eng)
{
    if (eng == GpgME::GpgEngine) {
        return i18nc("@title", "GPG (OpenPGP Backend) installation");
    } else if (eng == GpgME::GpgSMEngine) {
        return i18nc("@title", "GpgSM (S/MIME Backend) installation");
    } else if (eng == GpgME::GpgConfEngine) {
        return i18nc("@title", "GpgConf (Configuration) installation");
    }
    return QStringLiteral("unknown");
}

namespace
{

class EngineCheck : public SelfTestImplementation
{
public:
    explicit EngineCheck(GpgME::Engine eng)
        : SelfTestImplementation(test_name(eng))
    {
        runTest(eng);
    }

    void runTest(GpgME::Engine eng)
    {
        // First use the crypto config which is much faster because it is only
        // created once and then kept in memory. Only if the crypoconfig is
        // bad we check into the engine info.
        const auto conf = QGpgME::cryptoConfig();
        if (conf && eng == GpgME::GpgEngine) {
            m_passed = true;
            return;
        } else if (conf) {
            const auto comp = conf->component(engine_name(eng));
            if (comp) {
                m_passed = true;
                return;
            }
        }

        // Problem with the config. Try to get more details:
        const Error err = GpgME::checkEngine(eng);
        Q_ASSERT(!err.code() || err.code() == GPG_ERR_INV_ENGINE);

        m_passed = !err;

        if (m_passed) {
            return;
        }

        m_explanation = xi18nc("@info", "<para>A problem was detected with the <application>%1</application> backend.</para>", engine_name(eng));

        const EngineInfo ei = engineInfo(eng);
        if (ei.isNull()) {
            m_error = i18n("not supported");
            m_explanation += xi18nc("@info",
                                    "<para>It seems that the <icode>gpgme</icode> library was compiled without "
                                    "support for this backend.</para>");
            m_proposedFix += xi18nc("@info",
                                    "<para>Replace the <icode>gpgme</icode> library with a version compiled "
                                    "with <application>%1</application> support.</para>",
                                    engine_name(eng));
        } else if (ei.fileName() && (!ei.version() || !strcmp(ei.version(), "1.0.0"))) {
            // GPGSM only got the ei.version() working with 1.0.0 so 1.0.0 is returned as
            // a fallback if the version could not be checked. We assume that it's not properly
            // installed in that case.
            m_error = i18n("not properly installed");
            m_explanation += xi18nc("@info", "<para>Backend <command>%1</command> is not installed properly.</para>", QFile::decodeName(ei.fileName()));
            m_proposedFix +=
                xi18nc("@info", "<para>Please check the output of <command>%1 --version</command> manually.</para>", QFile::decodeName(ei.fileName()));
        } else if (ei.fileName() && ei.version() && ei.requiredVersion()) {
            m_error = i18n("too old");
            m_explanation += xi18nc("@info",
                                    "<para>Backend <command>%1</command> is installed in version %2, "
                                    "but at least version %3 is required.</para>",
                                    QFile::decodeName(ei.fileName()),
                                    QString::fromUtf8(ei.version()),
                                    QString::fromUtf8(ei.requiredVersion()));
            m_proposedFix += xi18nc("@info",
                                    "<para>Install <application>%1</application> version %2 or higher.</para>",
                                    engine_name(eng),
                                    QString::fromUtf8(ei.requiredVersion()));
        } else {
            m_error = m_explanation = i18n("unknown problem");
            m_proposedFix += xi18nc("@info",
                                    "<para>Make sure <application>%1</application> is installed and "
                                    "in <envar>PATH</envar>.</para>",
                                    engine_name(eng));
        }
    }
};
}

std::shared_ptr<SelfTest> Kleo::makeGpgEngineCheckSelfTest()
{
    return std::shared_ptr<SelfTest>(new EngineCheck(GpgME::GpgEngine));
}

std::shared_ptr<SelfTest> Kleo::makeGpgSmEngineCheckSelfTest()
{
    return std::shared_ptr<SelfTest>(new EngineCheck(GpgME::GpgSMEngine));
}

std::shared_ptr<SelfTest> Kleo::makeGpgConfEngineCheckSelfTest()
{
    return std::shared_ptr<SelfTest>(new EngineCheck(GpgME::GpgConfEngine));
}

//
// SelfTestImplementation (parts)
//

bool SelfTestImplementation::ensureEngineVersion(GpgME::Engine engine, int major, int minor, int patch)
{
    const Error err = GpgME::checkEngine(engine);
    Q_ASSERT(!err || err.code() == GPG_ERR_INV_ENGINE);

    m_skipped = err || !engineIsVersion(major, minor, patch, engine);

    if (!m_skipped) {
        return true;
    }

    const char *version = GpgME::engineInfo(engine).version();

    if (!err && version) {
        // properly installed, but too old
        m_explanation = xi18nc("@info",
                               "<para><application>%1</application> v%2.%3.%4 is required for this test, but only %5 is installed.</para>",
                               engine_name(engine),
                               major,
                               minor,
                               patch,
                               QString::fromUtf8(version));
        m_proposedFix += xi18nc("@info",
                                "<para>Install <application>%1</application> version %2 or higher.</para>",
                                engine_name(engine),
                                QStringLiteral("%1.%2.%3").arg(major).arg(minor).arg(patch));
    } else {
        // not properly installed
        m_explanation = xi18nc("@info",
                               "<para><application>%1</application> is required for this test, but does not seem available.</para>"
                               "<para>See tests further up for more information.</para>",
                               engine_name(engine));
        m_proposedFix = xi18nc("@info %1: test name", "<para>See \"%1\" above.</para>", test_name(engine));
    }

    return false;
}
