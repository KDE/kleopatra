/*
    aboutdata.cpp

    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2001, 2002, 2004 Klarälvdalens Datakonsult AB

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include <config-kleopatra.h>
#include <version-kleopatra.h>

#include "aboutdata.h"

#include "kleopatraapplication.h"

#include <Libkleo/GnuPG>

#include <QCoreApplication>
#include <QSettings>
#include <QThread>

#include <KLazyLocalizedString>
#include <KLocalizedString>

#include "kleopatra_debug.h"

/* Path to GnuPGs signing keys relative to the GnuPG installation */
#ifndef GNUPG_DISTSIGKEY_RELPATH
#define GNUPG_DISTSIGKEY_RELPATH "/../share/gnupg/distsigkey.gpg"
#endif
/* Path to a VERSION file relative to QCoreApplication::applicationDirPath */
#ifndef VERSION_RELPATH
#define VERSION_RELPATH "/../VERSION"
#endif

struct about_data {
    const KLazyLocalizedString name;
    const KLazyLocalizedString description;
};

static constexpr auto authors = std::to_array<about_data>({
    {kli18n("Ingo Klöcker"), kli18n("Maintainer")},
    {kli18n("Tobias Fella"), kli18n("Developer")},
    {kli18n("Andre Heinecke"), kli18n("Former Maintainer")},
    {kli18n("Marc Mutz"), kli18n("Former Maintainer")},
    {kli18n("Steffen Hansen"), kli18n("Former Maintainer")},
});

static constexpr auto credits = std::to_array<about_data>({
    {kli18n("Matthias Kalle Dalheimer"), kli18n("Original Author")},
    {kli18n("David Faure"), kli18n("Backend configuration framework, KIO integration")},
    {kli18n("Michel Boyer de la Giroday"), kli18n("Key-state dependent colors and fonts in the certificates list")},
    {kli18n("Thomas Moenicke"), kli18n("Artwork")},
    {kli18n("Frank Osterfeld"), kli18n("Resident gpgme/win wrangler, UI Server commands and dialogs")},
    {kli18n("Karl-Heinz Zimmer"), kli18n("DN display ordering support, infrastructure")},
    {kli18n("Laurent Montel"), kli18n("Qt5 port, general code maintenance")},
});

static void updateAboutDataFromSettings(KAboutData &about, const QSettings *settings)
{
    if (!settings) {
        return;
    }
    about.setDisplayName(settings->value(QStringLiteral("displayName"), about.displayName()).toString());
    about.setProductName(settings->value(QStringLiteral("productName"), about.productName()).toByteArray());
    about.setComponentName(settings->value(QStringLiteral("componentName"), about.componentName()).toString());
    about.setShortDescription(settings->value(QStringLiteral("shortDescription"), about.shortDescription()).toString());
    about.setHomepage(settings->value(QStringLiteral("homepage"), about.homepage()).toString());
    about.setBugAddress(settings->value(QStringLiteral("bugAddress"), about.bugAddress()).toByteArray());
    about.setVersion(settings->value(QStringLiteral("version"), about.version()).toByteArray());
    about.setOtherText(settings->value(QStringLiteral("otherText"), about.otherText()).toString());
    about.setCopyrightStatement(settings->value(QStringLiteral("copyrightStatement"), about.copyrightStatement()).toString());
    about.setDesktopFileName(settings->value(QStringLiteral("desktopFileName"), about.desktopFileName()).toString());
}

// Extend the about data with the used GnuPG Version since this can
// make a big difference with regards to the available features.
static void loadBackendVersions()
{
    auto thread = QThread::create([]() {
        STARTUP_TIMING << "Checking backend versions";
        const auto backendVersions = Kleo::backendVersionInfo();
        STARTUP_TIMING << "backend versions checked";
        if (!backendVersions.empty()) {
            QMetaObject::invokeMethod(qApp, [backendVersions]() {
                auto about = KAboutData::applicationData();
                about.setOtherText(i18nc("Preceeds a list of applications/libraries used by Kleopatra", "Uses:") //
                                   + QLatin1StringView{"<ul><li>"} //
                                   + backendVersions.join(QLatin1StringView{"</li><li>"}) //
                                   + QLatin1StringView{"</li></ul>"} //
                                   + about.otherText());
                KAboutData::setApplicationData(about);
            });
        }
    });
    thread->start();
}

// This code is mostly for Gpg4win and GnuPG VS-Desktop so that they
// can put in their own about data information.
static void loadCustomAboutData(KAboutData &about)
{
    const QStringList searchPaths = {Kleo::gnupgInstallPath()};
    const QString versionFile = QCoreApplication::applicationDirPath() + QStringLiteral(VERSION_RELPATH);
    const QString distSigKeys = Kleo::gnupgInstallPath() + QStringLiteral(GNUPG_DISTSIGKEY_RELPATH);
    STARTUP_TIMING << "Starting version info check";
    bool valid = Kleo::gpgvVerify(versionFile, QString(), distSigKeys, searchPaths);
    STARTUP_TIMING << "Version info checked";
    if (valid) {
        qCDebug(KLEOPATRA_LOG) << "Found valid VERSION file. Updating about data.";
        auto settings = std::make_shared<QSettings>(versionFile, QSettings::IniFormat);
        settings->beginGroup(QStringLiteral("Kleopatra"));
        updateAboutDataFromSettings(about, settings.get());
        KleopatraApplication::instance()->setDistributionSettings(settings);
    }
    loadBackendVersions();
}

AboutData::AboutData()
    : KAboutData(QStringLiteral("kleopatra"),
                 i18n("Kleopatra"),
                 QLatin1StringView(KLEOPATRA_VERSION_STRING),
                 i18n("Certificate manager and cryptography app"),
                 KAboutLicense::GPL,
                 i18nc("@info:credit", "(C) %1 g10 Code GmbH", QStringLiteral("2024")) + QLatin1Char('\n')
                     + i18nc("@info:credit", "(C) %1 The Kleopatra developers", QStringLiteral("2024")) + QLatin1Char('\n')
                     + i18nc("@info:credit", "(C) 2018 Intevation GmbH") + QLatin1Char('\n')
                     + i18nc("@info:credit", "(C) 2009 Klar\u00E4lvdalens\u00A0Datakonsult\u00A0AB"))
{
    using ::authors;
    using ::credits;

    for (const auto &author : authors) {
        addAuthor(author.name.toString(), author.description.toString());
    }

    for (const auto &credit : credits) {
        addCredit(credit.name.toString(), credit.description.toString());
    }

    loadCustomAboutData(*this);
}
