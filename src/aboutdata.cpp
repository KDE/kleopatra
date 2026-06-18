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

#include <utils/distributiondata.h>
#include <utils/qt6compat.h>

#include <Libkleo/GnuPG>

#include <QFile>
#include <QSettings>
#include <QTextCodec>
#include <QThread>

#include <KLazyLocalizedString>
#include <KLocalizedString>

#include "kleopatra_debug.h"

using namespace Qt::Literals::StringLiterals;

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
    {kli18n("Frank Osterfeld"), kli18n("Resident gpgme/win wrangler, UI Server commands and dialogs")},
    {kli18n("Karl-Heinz Zimmer"), kli18n("DN display ordering support, infrastructure")},
    {kli18n("Laurent Montel"), kli18n("Qt5 port, general code maintenance")},
    {kli18n("Matthias Kalle Dalheimer"), kli18n("Original Author")},
    {kli18n("Michel Boyer de la Giroday"), kli18n("Key-state dependent colors and fonts in the certificates list")},
    {kli18n("Thomas Moenicke"), kli18n("Artwork")},
});

#if KLEOPATRA_FEATURE_READ_VERSION_FILE
static void updateAboutData(KAboutData &about, const DistributionData &data)
{
    about.setDisplayName(data.displayName.value_or(about.displayName()));
    about.setProductName(data.productName.value_or(about.productName()).toUtf8());
    about.setComponentName(data.componentName.value_or(about.componentName()));
    about.setShortDescription(data.shortDescription.value_or(about.shortDescription()));
    about.setHomepage(data.homepage.value_or(about.homepage()));
    about.setBugAddress(data.bugAddress.value_or(about.bugAddress()).toUtf8());
    about.setVersion(data.version.value_or(about.version()).toUtf8());
    about.setOtherText(data.otherText.value_or(about.otherText()));
    about.setCopyrightStatement(data.copyrightStatement.value_or(about.copyrightStatement()));
    about.setDesktopFileName(data.desktopFileName.value_or(about.desktopFileName()));
}
#endif

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
                                   + QLatin1String{"<ul><li>"} //
                                   + backendVersions.join(QLatin1String{"</li><li>"}) //
                                   + QLatin1String{"</li></ul>"} //
                                   + about.otherText());
                KAboutData::setApplicationData(about);
            });
        }
    });
    thread->start();
}

#if KLEOPATRA_FEATURE_READ_VERSION_FILE
static auto toOptionalString(const QVariant &value)
{
    return value.isValid() ? std::make_optional(value.toString()) : std::nullopt;
}
#endif

// This code is mostly for Gpg4win and GnuPG VS-Desktop so that they
// can put in their own about data information.
static void loadCustomAboutData([[maybe_unused]] KAboutData &about)
{
#if KLEOPATRA_FEATURE_READ_VERSION_FILE
    const QString versionFile = QCoreApplication::applicationDirPath() + QStringLiteral(VERSION_RELPATH);
    auto distributionData = std::make_shared<DistributionData>();
    qCDebug(KLEOPATRA_LOG) << "Looking for VERSION file:" << versionFile;
    if (QFile::exists(versionFile)) {
        const QStringList searchPaths = {Kleo::gnupgInstallPath()};
        const QString distSigKeys = Kleo::gnupgInstallPath() + QStringLiteral(GNUPG_DISTSIGKEY_RELPATH);
        STARTUP_TIMING << "Starting check of VERSION file";
        distributionData->isValid = Kleo::gpgvVerify(versionFile, QString(), distSigKeys, searchPaths);
        STARTUP_TIMING << "Finished check of VERSION file";
        if (distributionData->isValid) {
            qCDebug(KLEOPATRA_LOG) << "VERSION file is valid. Updating about data.";
            QSettings settings(versionFile, QSettings::IniFormat);
            settings.setIniCodec(QTextCodec::codecForName("UTF-8"));
            settings.beginGroup(QStringLiteral("Kleopatra"));
            distributionData->displayName = toOptionalString(settings.value(u"displayName"_s));
            distributionData->productName = toOptionalString(settings.value(u"productName"_s));
            distributionData->componentName = toOptionalString(settings.value(u"componentName"_s));
            distributionData->shortDescription = toOptionalString(settings.value(u"shortDescription"_s));
            distributionData->homepage = toOptionalString(settings.value(u"homepage"_s));
            distributionData->bugAddress = toOptionalString(settings.value(u"bugAddress"_s));
            distributionData->version = toOptionalString(settings.value(u"version"_s));
            distributionData->otherText = toOptionalString(settings.value(u"otherText"_s));
            distributionData->copyrightStatement = toOptionalString(settings.value(u"copyrightStatement"_s));
            distributionData->desktopFileName = toOptionalString(settings.value(u"desktopFileName"_s));
            distributionData->uidComment = toOptionalString(settings.value(u"uidcomment"_s));
            distributionData->statusLine = toOptionalString(settings.value(u"statusline"_s));
            updateAboutData(about, *distributionData.get());
        } else {
            qCWarning(KLEOPATRA_LOG) << "VERSION file is NOT valid. The installation is corrupt.";
            distributionData->detailedError = xi18nc("@info:tooltip", "The verification of the file <filename>%1</filename> failed.", versionFile);
        }
    } else {
        qCWarning(KLEOPATRA_LOG) << "VERSION file is missing. The installation is corrupt.";
        distributionData->detailedError = xi18nc("@info:tooltip", "The file <filename>%1</filename> is missing.", versionFile);
    }
    KleopatraApplication::instance()->setDistributionData(distributionData);
#endif
    loadBackendVersions();
}

AboutData::AboutData()
    : KAboutData(QStringLiteral("kleopatra"),
                 i18n("Kleopatra"),
                 QLatin1String(kleopatra_version),
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

    loadCustomAboutData(*this);
}
