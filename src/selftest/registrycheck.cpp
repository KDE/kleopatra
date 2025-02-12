/*
    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2008 Klarälvdalens Datakonsult AB

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include <config-kleopatra.h>

#include "registrycheck.h"

#include "implementation_p.h"

#include <KLocalizedString>
#include <KMessageBox>

#include <QSettings>

using namespace Kleo;
using namespace Kleo::_detail;

static QString gnupg_path = QStringLiteral("HKEY_LOCAL_MACHINE\\Software\\GNU\\GnuPG");
static QString gnupg_key = QStringLiteral("gpgProgram");

namespace
{

class RegistryCheck : public SelfTestImplementation
{
public:
    explicit RegistryCheck()
        : SelfTestImplementation(i18nc("@title", "Windows Registry"))
    {
        runTest();
    }

    void runTest()
    {
        m_passed = !QSettings(gnupg_path, QSettings::NativeFormat).contains(gnupg_key);

        if (m_passed) {
            return;
        }

        m_error = i18n("Obsolete registry entries found");

        m_explanation = xi18nc("@info",
                               "<para>Kleopatra detected an obsolete registry key (<resource>%1\\%2</resource>), "
                               "added by either a previous <application>Gpg4win</application> version or "
                               "applications such as <application>WinPT</application> or <application>EnigMail</application>.</para>"
                               "<para>Keeping the entry might lead to an old GnuPG backend being used.</para>",
                               gnupg_path,
                               gnupg_key);
        m_proposedFix = xi18nc("@info", "<para>Delete registry key <resource>%1\\%2</resource>.</para>", gnupg_path, gnupg_key);
    }

    /* reimp */ bool canFixAutomatically() const override
    {
        return true;
    }

    /* reimp */ bool fix() override
    {
        QSettings settings(gnupg_path, QSettings::NativeFormat);
        if (!settings.contains(gnupg_key)) {
            return true;
        }

        settings.remove(gnupg_key);
        settings.sync();

        if (settings.status() != QSettings::NoError) {
            KMessageBox::error(nullptr,
                               xi18nc("@info", "Could not delete the registry key <resource>%1\\%2</resource>", gnupg_path, gnupg_key),
                               i18nc("@title", "Error Deleting Registry Key"));
            return false;
        }

        m_passed = true;
        m_error.clear();
        m_explanation.clear();
        m_proposedFix.clear();
        return true;
    }
};
}

std::shared_ptr<SelfTest> Kleo::makeGpgProgramRegistryCheckSelfTest()
{
    return std::shared_ptr<SelfTest>(new RegistryCheck);
}
