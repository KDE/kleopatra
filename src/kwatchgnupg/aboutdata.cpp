/*
    aboutdata.cpp

    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2004 Klarälvdalens Datakonsult AB

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include "aboutdata.h"

#include <version-kwatchgnupg.h>

#include <KLocalizedString>
#include <array>

#include <KLazyLocalizedString>

struct about_data {
    const KLazyLocalizedString name;
    const KLazyLocalizedString desc;
};

static constexpr auto authors = std::to_array<about_data>({
    {kli18n("Steffen Hansen"), kli18n("Original Author")},
});

AboutData::AboutData()
    : KAboutData(QStringLiteral("kwatchgnupg"),
                 i18nc("@title", "GnuPG Log Viewer"),
                 QLatin1StringView(KWATCHGNUPG_VERSION_STRING),
                 i18nc("@info", "Viewer for GnuPG daemon and application logs"),
                 KAboutLicense::GPL,
                 i18nc("@info:credit", "(C) 2019-%1 g10 Code GmbH", QStringLiteral("2024")) + QLatin1Char('\n')
                     + i18n("(C) 2001-2004 Klar\xC3\xA4lvdalens Datakonsult AB\n"))
{
    using ::authors;
    for (const auto &author : authors) {
        addAuthor(KLocalizedString(author.name).toString(), KLocalizedString(author.desc).toString());
    }
}
