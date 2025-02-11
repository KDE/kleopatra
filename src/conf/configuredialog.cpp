/*
    This file is part of kleopatra
    SPDX-FileCopyrightText: 2000 Espen Sand <espen@kde.org>
    SPDX-FileCopyrightText: 2001-2002 Marc Mutz <mutz@kde.org>
    SPDX-FileCopyrightText: 2004, 2008 Klarälvdalens Datakonsult AB

    SPDX-FileCopyrightText: 2016 Bundesamt für Sicherheit in der Informationstechnik
    SPDX-FileContributor: Intevation GmbH

    SPDX-License-Identifier: GPL-2.0-only
*/

#include "configuredialog.h"

#include "settings.h"

#include <KConfig>
#include <KConfigGroup>
#include <KLocalizedString>
#include <KSharedConfig>

#include "conf/appearanceconfigpage.h"
#include "conf/cryptooperationsconfigpage.h"
#include "conf/dirservconfigpage.h"
#include "conf/gnupgsystemconfigurationpage.h"
#include "conf/smartcardconfigpage.h"
#include "conf/smimevalidationconfigurationpage.h"

ConfigureDialog::ConfigureDialog(QWidget *parent)
    : KleoPageConfigDialog(parent)
{
    setFaceType(KPageDialog::List);
    setWindowTitle(i18nc("@title:window", "Configure"));

    const auto settings = Kleo::Settings{};
    if (settings.showDirectoryServicesConfiguration()) {
        addModule(i18n("Directory Services"),
                  QStringLiteral("kleopatra/configuration.html#configuration-directory-services"),
                  QStringLiteral("view-certificate-server-configure"),
                  new DirectoryServicesConfigurationPage(this));
    }
    if (settings.showAppearanceConfiguration()) {
        addModule(i18n("Appearance"),
                  QStringLiteral("kleopatra/configuration-appearance.html"),
                  QStringLiteral("applications-graphics"),
                  new Kleo::Config::AppearanceConfigurationPage(this));
    }
    if (settings.showCryptoOperationsConfiguration()) {
        addModule(i18n("Crypto Operations"),
                  QStringLiteral("kleopatra/configuration-cryptooperations.html"),
                  QStringLiteral("document-encrypt"),
                  new Kleo::Config::CryptoOperationsConfigurationPage(this));
    }
    if (settings.showSMimeValidationConfiguration() && settings.cmsEnabled()) {
        addModule(i18n("S/MIME Validation"),
                  QStringLiteral("kleopatra/configuration.html#configuration-smime-validation"),
                  QStringLiteral("preferences-system-network"),
                  new Kleo::Config::SMimeValidationConfigurationPage(this));
    }
    if (settings.showSmartCardsConfiguration()) {
        addModule(i18n("Smart Cards"),
                  QStringLiteral("kleopatra/configuration.html"),
                  QStringLiteral("auth-sim-locked"),
                  new Kleo::Config::SmartCardConfigurationPage{this});
    }
    if (settings.showGnuPGSystemConfiguration()) {
        addModule(i18n("GnuPG System"),
                  QStringLiteral("kleopatra/configuration.html#configuration-gnupgsystem"),
                  QStringLiteral("document-encrypt"),
                  new Kleo::Config::GnuPGSystemConfigurationPage(this));
    }

    // We store the minimum size of the dialog on hide, because otherwise
    // the KCMultiDialog starts with the size of the first kcm, not
    // the largest one. This way at least after the first showing of
    // the largest kcm the size is kept.
    const KConfigGroup geometry(KSharedConfig::openStateConfig(), QStringLiteral("Geometry"));
    const int width = geometry.readEntry("ConfigureDialogWidth", 0);
    const int height = geometry.readEntry("ConfigureDialogHeight", 0);
    if (width != 0 && height != 0) {
        setMinimumSize(width, height);
    }
}

void ConfigureDialog::hideEvent(QHideEvent *e)
{
    const QSize minSize = minimumSizeHint();
    KConfigGroup geometry(KSharedConfig::openStateConfig(), QStringLiteral("Geometry"));
    geometry.writeEntry("ConfigureDialogWidth", minSize.width());
    geometry.writeEntry("ConfigureDialogHeight", minSize.height());
    KleoPageConfigDialog::hideEvent(e);
}

#include "moc_configuredialog.cpp"
