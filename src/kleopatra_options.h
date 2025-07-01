/*
    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2015 Bundesamt für Sicherheit in der Informationstechnik
    SPDX-FileContributor: Intevation GmbH

    SPDX-License-Identifier: GPL-2.0-or-later
*/
#pragma once

#include <config-kleopatra.h>

#include <KLocalizedString>
#include <QCommandLineParser>

static void kleopatra_options(QCommandLineParser *parser)
{
    using namespace Qt::StringLiterals;

    parser->addOptions({
        QCommandLineOption({QStringLiteral("openpgp"), QStringLiteral("p")}, i18nc("@info:shell", "Use OpenPGP for the following operation")),
        QCommandLineOption({QStringLiteral("cms"), QStringLiteral("c")}, i18nc("@info:shell", "Use CMS (X.509, S/MIME) for the following operation")),
        QCommandLineOption(QStringLiteral("uiserver-socket"),
                           i18nc("@info:shell", "Location of the socket the ui server is listening on"),
                           QStringLiteral("argument")),
        QCommandLineOption(QStringLiteral("daemon"), i18nc("@info:shell", "Run UI server only, hide main window")),
        QCommandLineOption({QStringLiteral("import-certificate"), QStringLiteral("i")}, i18nc("@info:shell", "Import certificate file(s)")),
        QCommandLineOption({QStringLiteral("encrypt"), QStringLiteral("e")}, i18nc("@info:shell", "Encrypt file(s)")),
        QCommandLineOption({QStringLiteral("sign"), QStringLiteral("s")}, i18nc("@info:shell", "Sign file(s)")),
        QCommandLineOption({QStringLiteral("sign-encrypt"), QStringLiteral("E")}, i18nc("@info:shell", "Sign and/or encrypt file(s)")),
        QCommandLineOption(QStringLiteral("encrypt-sign"), i18nc("@info:shell", "Same as --sign-encrypt, do not use")),
        QCommandLineOption({QStringLiteral("decrypt"), QStringLiteral("d")}, i18nc("@info:shell", "Decrypt file(s)")),
        QCommandLineOption({QStringLiteral("verify"), QStringLiteral("V")}, i18nc("@info:shell", "Verify file/signature")),
        QCommandLineOption({QStringLiteral("decrypt-verify"), QStringLiteral("D")}, i18nc("@info:shell", "Decrypt and/or verify file(s)")),
        QCommandLineOption(QStringLiteral("search"), i18nc("@info:shell", "Search for a certificate on a keyserver")),
        QCommandLineOption(QStringLiteral("checksum"), i18nc("@info:shell", "Create or check a checksum file")),
        QCommandLineOption({QStringLiteral("query"), QStringLiteral("q")},
                           i18nc("If a certificate is already known it shows the certificate details dialog. "
                                 "Otherwise it brings up the certificate search dialog.",
                                 "Show details of a local certificate or search for it on a keyserver by fingerprint")),
        QCommandLineOption(QStringLiteral("gen-key"), i18nc("@info:shell", "Create a new key pair or certificate signing request")),
        QCommandLineOption(QStringLiteral("parent-windowid"), i18nc("@info:shell", "Parent Window Id for dialogs"), QStringLiteral("windowId")),
        QCommandLineOption(QStringLiteral("config"), i18nc("@info:shell", "Open the config dialog")),
        QCommandLineOption(u"standalone"_s, i18nc("@info:shell", "Run as standalone app without system tray icon")),
    });

    /* Security note: To avoid code execution by shared library injection
     * through e.g. -platformpluginpath any external input should be seperated
     * by a double dash -- this is why query / search uses positional arguments.
     *
     * For example on Windows there is an URLhandler for openpgp4fpr:
     * be opened with Kleopatra's query function. And while a browser should
     * urlescape such a query there might be tricks to inject a quote character
     * and as such inject command line options for Kleopatra in an URL. */
    parser->addPositionalArgument(QStringLiteral("files"), i18nc("@info:shell", "File(s) to process"), QStringLiteral("-- [files..]"));
    parser->addPositionalArgument(QStringLiteral("query"), i18nc("@info:shell", "String or Fingerprint for query and search"), QStringLiteral("-- [query..]"));
}
