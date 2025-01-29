/* -*- mode: c++; c-basic-offset:4 -*-
    commands/exportopenpgpcertstoservercommand.cpp

    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2008 Klarälvdalens Datakonsult AB

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include <config-kleopatra.h>

#include "exportopenpgpcertstoservercommand.h"

#include "command_p.h"
#include <settings.h>

#include <Libkleo/Algorithm>
#include <Libkleo/Formatting>
#include <Libkleo/GnuPG>
#include <Libkleo/KeyHelpers>

#include <gpgme++/key.h>

#include <KLocalizedString>
#include <KMessageBox>

using namespace Kleo;
using namespace Kleo::Commands;
using namespace GpgME;

ExportOpenPGPCertsToServerCommand::ExportOpenPGPCertsToServerCommand(KeyListController *c)
    : GnuPGProcessCommand(c)
{
}

ExportOpenPGPCertsToServerCommand::ExportOpenPGPCertsToServerCommand(QAbstractItemView *v, KeyListController *c)
    : GnuPGProcessCommand(v, c)
{
}

ExportOpenPGPCertsToServerCommand::ExportOpenPGPCertsToServerCommand(const Key &key)
    : GnuPGProcessCommand(key)
{
}

ExportOpenPGPCertsToServerCommand::ExportOpenPGPCertsToServerCommand(const std::vector<Key> &keys)
    : GnuPGProcessCommand(keys)
{
}

ExportOpenPGPCertsToServerCommand::~ExportOpenPGPCertsToServerCommand() = default;

Command::Restrictions ExportOpenPGPCertsToServerCommand::restrictions()
{
    if (Settings{}.allowPublicKeyUpload()) {
        return MustBeOpenPGP;
    } else {
        return MustBeOpenPGP | NeedSecretKey;
    }
}

static bool confirmExport(const std::vector<Key> &pgpKeys, QWidget *parentWidget)
{
    auto notCertifiedKeys = std::accumulate(pgpKeys.cbegin(), pgpKeys.cend(), QStringList{}, [](auto keyNames, const auto &key) {
        const bool allValidUserIDsAreCertifiedByUser = std::ranges::all_of(key.userIDs(), [](const UserID &userId) {
            return userId.isBad() || Kleo::userIDIsCertifiedByUser(userId);
        });
        if (!allValidUserIDsAreCertifiedByUser) {
            keyNames.push_back(Formatting::formatForComboBox(key));
        }
        return keyNames;
    });
    if (!notCertifiedKeys.empty()) {
        if (pgpKeys.size() == 1) {
            const auto answer = KMessageBox::warningContinueCancel( //
                parentWidget,
                xi18nc("@info",
                       "<para>You haven't certified all valid user IDs of this certificate "
                       "with an exportable certification. People relying on your certifications "
                       "may not be able to verify the certificate.</para>"
                       "<para>Do you want to continue the export?</para>"),
                i18nc("@title:window", "Confirm Certificate Export"),
                KGuiItem{i18ncp("@action:button", "Export Certificate", "Export Certificates", 1)},
                KStandardGuiItem::cancel(),
                QStringLiteral("confirm-upload-of-uncertified-keys"));
            return answer == KMessageBox::Continue;
        } else {
            std::sort(notCertifiedKeys.begin(), notCertifiedKeys.end());
            const auto answer = KMessageBox::warningContinueCancelList( //
                parentWidget,
                xi18nc("@info",
                       "<para>You haven't certified all valid user IDs of the certificates listed below "
                       "with exportable certifications. People relying on your certifications "
                       "may not be able to verify the certificates.</para>"
                       "<para>Do you want to continue the export?</para>"),
                notCertifiedKeys,
                i18nc("@title:window", "Confirm Certificate Export"),
                KGuiItem{i18ncp("@action:button", "Export Certificate", "Export Certificates", pgpKeys.size())},
                KStandardGuiItem::cancel(),
                QStringLiteral("confirm-upload-of-uncertified-keys"));
            return answer == KMessageBox::Continue;
        }
    }

    return true;
}

bool ExportOpenPGPCertsToServerCommand::preStartHook(QWidget *parent) const
{
    if (!haveKeyserverConfigured()) {
        d->error(i18ncp("@info",
                        "Exporting the certificate to a key server is not possible "
                        "because the usage of key servers has been disabled explicitly.",
                        "Exporting the certificates to a key server is not possible "
                        "because the usage of key servers has been disabled explicitly.",
                        d->keys().size()));
        return false;
    }
    if (interactive() && !confirmExport(d->keys(), parent)) {
        return false;
    }

    return !interactive() || keyserver().startsWith(QLatin1String("ldap"))
        || KMessageBox::warningContinueCancel(
               parent,
               xi18nc("@info",
                      "<para>When OpenPGP certificates have been exported to a public directory server, "
                      "it is nearly impossible to remove them again.</para>"
                      "<para>Before exporting your certificate to a public directory server, make sure that you "
                      "have created a revocation certificate so you can revoke the certificate if it is compromised, lost, or you forgot the passphrase.</para>"
                      "<para>Are you sure you want to continue?</para>"),
               i18nc("@title:window", "OpenPGP Certificate Export"),
               KGuiItem{i18ncp("@action:button", "Export Certificate", "Export Certificates", d->keys().size())},
               KStandardGuiItem::cancel(),
               QStringLiteral("warn-export-openpgp-nonrevocable"))
        == KMessageBox::Continue;
}

QStringList ExportOpenPGPCertsToServerCommand::arguments() const
{
    QStringList result;
    result << gpgPath();
    result << QStringLiteral("--send-keys");
    const auto keys = d->keys();
    for (const Key &key : keys) {
        result << QLatin1String(key.primaryFingerprint());
    }
    return result;
}

QString ExportOpenPGPCertsToServerCommand::errorCaption() const
{
    return i18nc("@title:window", "OpenPGP Certificate Export Error");
}

QString ExportOpenPGPCertsToServerCommand::successCaption() const
{
    return {};
}

QString ExportOpenPGPCertsToServerCommand::crashExitMessage(const QStringList &args) const
{
    return xi18nc("@info",
                  "<para>The GPG process that tried to export OpenPGP certificates "
                  "ended prematurely because of an unexpected error.</para>"
                  "<para>Please check the output of <icode>%1</icode> for details.</para>",
                  args.join(QLatin1Char(' ')));
}

QString ExportOpenPGPCertsToServerCommand::errorExitMessage(const QStringList &args) const
{
    // ki18n(" ") as initializer because initializing with empty string leads to
    // (I18N_EMPTY_MESSAGE)
    const auto errorLines = errorString().split(QLatin1Char{'\n'});
    const auto errorText = std::accumulate(errorLines.begin(), errorLines.end(), KLocalizedString{ki18n(" ")}, [](KLocalizedString temp, const auto &line) {
        return kxi18nc("@info used for concatenating multiple lines of text with line breaks; most likely this shouldn't be translated", "%1<nl />%2")
            .subs(temp)
            .subs(line);
    });
    return xi18nc("@info",
                  "<para>An error occurred while trying to export OpenPGP certificates.</para> "
                  "<para>The output of <command>%1</command> was:<nl /><message>%2</message></para>",
                  args[0],
                  errorText);
}

QString ExportOpenPGPCertsToServerCommand::successMessage(const QStringList &) const
{
    return i18nc("@info", "Upload successful.");
}
