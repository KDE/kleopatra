/*
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
#include <QFile>
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

using namespace Qt::Literals::StringLiterals;

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
    {kli18n("Alexander Kulbartsch"), kli18nc("@info:credit", "UX redesign of smartcard view and certificate details")},
    {kli18n("Carl Schwan"), kli18nc("@info:credit", "Mail viewer")},
    {kli18n("David Faure"), kli18n("Backend configuration framework, KIO integration")},
    {kli18n("Frank Osterfeld"), kli18n("UI Server commands and dialogs")},
    {kli18n("Karl-Heinz Zimmer"), kli18n("DN display ordering support, infrastructure")},
    {kli18n("Laurent Montel"), kli18n("Qt5 port, general code maintenance")},
    {kli18n("Matthias Kalle Dalheimer"), kli18n("Original Author")},
    {kli18n("Michel Boyer de la Giroday"), kli18n("Key-state dependent colors and fonts in the certificates list")},
    {kli18n("Thomas Moenicke"), kli18n("Artwork")},
    {kli18n("Werner Koch"), kli18n("GnuPG consulting")},
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
        const auto backendComponents = Kleo::backendComponents();
        STARTUP_TIMING << "backend versions checked";
        if (!backendComponents.empty()) {
            QMetaObject::invokeMethod(qApp, [backendComponents]() {
                auto about = KAboutData::applicationData();
                for (const auto &component : backendComponents) {
                    about.addComponent(component);
                }
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
    const QString versionFile = QCoreApplication::applicationDirPath() + QStringLiteral(VERSION_RELPATH);
    if (QFile::exists(versionFile)) {
        const QStringList searchPaths = {Kleo::gnupgInstallPath()};
        const QString distSigKeys = Kleo::gnupgInstallPath() + QStringLiteral(GNUPG_DISTSIGKEY_RELPATH);
        STARTUP_TIMING << "Starting version info check";
        const bool valid = Kleo::gpgvVerify(versionFile, QString(), distSigKeys, searchPaths);
        STARTUP_TIMING << "Version info checked";
        if (valid) {
            qCDebug(KLEOPATRA_LOG) << "Found valid VERSION file. Updating about data.";
            auto settings = std::make_shared<QSettings>(versionFile, QSettings::IniFormat);
            settings->beginGroup(QStringLiteral("Kleopatra"));
            updateAboutDataFromSettings(about, settings.get());
            KleopatraApplication::instance()->setDistributionSettings(settings);
        }
    }
    loadBackendVersions();
}

AboutData::AboutData()
    : KAboutData(QStringLiteral("kleopatra"),
                 i18n("Kleopatra"),
                 QLatin1StringView(KLEOPATRA_VERSION_STRING),
                 i18n("Certificate manager and cryptography app"),
                 KAboutLicense::GPL,
                 i18nc("@info:credit", "\u00A9 2019-%1 g10 Code GmbH", QStringLiteral("2024")) + QLatin1Char('\n')
                     + i18nc("@info:credit", "\u00A9 2015-2018 Intevation GmbH") + QLatin1Char('\n')
                     + i18nc("@info:credit", "\u00A9 2015-2018 Bundesamt für Sicherheit in der Informationstechnik") + QLatin1Char('\n')
                     + i18nc("@info:credit", "\u00A9 2001-2010 Klar\u00E4lvdalens\u00A0Datakonsult\u00A0AB") + QLatin1Char('\n')
                     + i18nc("@info:credit", "\u00A9 2001-%1 The Kleopatra developers", QStringLiteral("2024")))
{
    using ::authors;
    using ::credits;

    setOrganizationDomain(KLEOPATRA_ORGANIZATION_DOMAIN);

    for (const auto &author : authors) {
        addAuthor(author.name.toString(), author.description.toString());
    }

    for (const auto &credit : credits) {
        addCredit(credit.name.toString(), credit.description.toString());
    }

#if KLEOPATRA_LIST_AS_COMPONENT
    const QLatin1StringView commitId{KLEOPATRA_COMMIT_ID};
    if (!commitId.isEmpty()) {
        addComponent(i18n("Kleopatra"), i18n("Certificate manager and cryptography app"), commitId, u"https://apps.kde.org/kleopatra"_s, KAboutLicense::GPL);
    }
#endif

    loadCustomAboutData(*this);
}
