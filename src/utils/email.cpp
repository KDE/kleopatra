/* -*- mode: c++; c-basic-offset:4 -*-
    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2008 Klarälvdalens Datakonsult AB
    SPDX-FileCopyrightText: 2016, 2017 Bundesamt für Sicherheit in der Informationstechnik
    SPDX-FileContributor: Intevation GmbH
    SPDX-FileCopyrightText: 2022 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include "email.h"

#include <KLocalizedString>

#include <QDesktopServices>
#include <QFileInfo>
#include <QUrlQuery>

#include <kleopatra_debug.h>

void Kleo::invokeMailer(const QString &subject, const QString &body, const QFileInfo &attachment)
{
    invokeMailer({}, subject, body, attachment);
}

void Kleo::invokeMailer(const QString &to, const QString &subject, const QString &body, const QFileInfo &attachment)
{
    const auto attachmentPath = attachment.filePath();
    qCDebug(KLEOPATRA_LOG) << __func__ << "to:" << to << "subject:" << subject << "body:" << body << "attachment:" << attachmentPath;

    // RFC 2368 says body's linebreaks need to be encoded as
    // "%0D%0A", so normalize body to CRLF:
    // body.replace(QLatin1Char('\n'), QStringLiteral("\r\n")).remove(QStringLiteral("\r\r"));

    QUrlQuery query;
    query.addQueryItem(QStringLiteral("subject"), subject);
    query.addQueryItem(QStringLiteral("body"), body);
    if (!attachmentPath.isEmpty()) {
        query.addQueryItem(QStringLiteral("attach"), attachmentPath);
    }
    QUrl url;
    url.setScheme(QStringLiteral("mailto"));
    url.setPath(to);
    url.setQuery(query);
    qCDebug(KLEOPATRA_LOG) << __func__ << "Calling QDesktopServices::openUrl" << url;
    QDesktopServices::openUrl(url);
}
