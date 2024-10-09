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

static const char kleopatra_version[] = KLEOPATRA_VERSION_STRING;

struct about_data {
    const KLazyLocalizedString name;
    const KLazyLocalizedString desc;
    const char *email;
    const char *web;
};

static const about_data authors[] = {
    {kli18n("Andre Heinecke (g10 Code)"), kli18n("Developer"), "aheinecke@gnupg.org", nullptr},
    {kli18n("Ingo Klöcker (g10 Code)"), kli18n("Developer"), "dev@ingo-kloecker.de", nullptr},
    {kli18n("Tobias Fella (g10 Code)"), kli18n("Developer"), "tobias.fella@gnupg.com", nullptr},
};

static const about_data credits[] = {
    {kli18n("Marc Mutz"), kli18n("Former Maintainer"), "mutz@kde.org", nullptr},
    {kli18n("Steffen Hansen"), kli18n("Former Maintainer"), "hansen@kde.org", nullptr},
    {kli18n("Matthias Kalle Dalheimer"), kli18n("Original Author"), "kalle@kde.org", nullptr},
    {kli18n("David Faure"), kli18n("Backend configuration framework, KIO integration"), "faure@kde.org", nullptr},
    {kli18n("Michel Boyer de la Giroday"),
     kli18n("Key-state dependent colors and fonts in the certificates list"),
     "michel@klaralvdalens-datakonsult.se",
     nullptr},
    {kli18n("Thomas Moenicke"), kli18n("Artwork"), "tm@php-qt.org", nullptr},
    {kli18n("Frank Osterfeld"), kli18n("Resident gpgme/win wrangler, UI Server commands and dialogs"), "osterfeld@kde.org", nullptr},
    {kli18n("Karl-Heinz Zimmer"), kli18n("DN display ordering support, infrastructure"), "khz@kde.org", nullptr},
    {kli18n("Laurent Montel"), kli18n("Qt5 port, general code maintenance"), "montel@kde.org", nullptr},
};

static void updateAboutDataFromSettings(KAboutData *about, const QSettings *settings)
{
    if (!about || !settings) {
        return;
    }
    about->setDisplayName(settings->value(QStringLiteral("displayName"), about->displayName()).toString());
    about->setProductName(settings->value(QStringLiteral("productName"), about->productName()).toByteArray());
    about->setComponentName(settings->value(QStringLiteral("componentName"), about->componentName()).toString());
    about->setShortDescription(settings->value(QStringLiteral("shortDescription"), about->shortDescription()).toString());
    about->setHomepage(settings->value(QStringLiteral("homepage"), about->homepage()).toString());
    about->setBugAddress(settings->value(QStringLiteral("bugAddress"), about->bugAddress()).toByteArray());
    about->setVersion(settings->value(QStringLiteral("version"), about->version()).toByteArray());
    about->setOtherText(settings->value(QStringLiteral("otherText"), about->otherText()).toString());
    about->setCopyrightStatement(settings->value(QStringLiteral("copyrightStatement"), about->copyrightStatement()).toString());
    about->setDesktopFileName(settings->value(QStringLiteral("desktopFileName"), about->desktopFileName()).toString());
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
static void loadCustomAboutData(KAboutData *about)
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
                 QLatin1StringView(kleopatra_version),
                 i18n("Certificate Manager and Unified Crypto GUI"),
                 KAboutLicense::GPL,
                 i18n("(c) 2002 Steffen\u00A0Hansen, Matthias\u00A0Kalle\u00A0Dalheimer, Klar\u00E4lvdalens\u00A0Datakonsult\u00A0AB\n"
                      "(c) 2004, 2007, 2008, 2009 Marc\u00A0Mutz, Klar\u00E4lvdalens\u00A0Datakonsult\u00A0AB") //
                     + QLatin1Char('\n') //
                     + i18n("(c) 2016-2018 Intevation GmbH") //
                     + QLatin1Char('\n') //
                     + i18n("(c) 2010-%1 The Kleopatra developers, g10 Code GmbH", QStringLiteral("2024")))
{
    using ::authors;
    using ::credits;
    for (unsigned int i = 0; i < sizeof authors / sizeof *authors; ++i) {
        addAuthor(KLocalizedString(authors[i].name).toString(),
                  KLocalizedString(authors[i].desc).toString(),
                  QLatin1StringView(authors[i].email),
                  QLatin1StringView(authors[i].web));
    }
    for (unsigned int i = 0; i < sizeof credits / sizeof *credits; ++i) {
        addCredit(KLocalizedString(credits[i].name).toString(),
                  KLocalizedString(credits[i].desc).toString(),
                  QLatin1StringView(credits[i].email),
                  QLatin1StringView(credits[i].web));
    }

    loadCustomAboutData(this);
}
