/*
    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2008 Klarälvdalens Datakonsult AB

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include <config-kleopatra.h>

#include "refreshx509certscommand.h"

#include <Libkleo/GnuPG>

#include <KLocalizedString>
#include <KMessageBox>

using namespace Kleo;
using namespace Kleo::Commands;

RefreshX509CertsCommand::RefreshX509CertsCommand(KeyListController *c)
    : GnuPGProcessCommand(c)
{
}

RefreshX509CertsCommand::RefreshX509CertsCommand(QAbstractItemView *v, KeyListController *c)
    : GnuPGProcessCommand(v, c)
{
}

RefreshX509CertsCommand::~RefreshX509CertsCommand()
{
}

/* aheinecke 2020: I think it's ok to use X.509 here in the windows because
 * this is an expert thing and normally not used. */
bool RefreshX509CertsCommand::preStartHook(QWidget *parent) const
{
    return KMessageBox::warningContinueCancel(parent,
                                              xi18nc("@info",
                                                     "<para>Refreshing X.509 certificates implies downloading CRLs for all certificates, "
                                                     "even if they might otherwise still be valid.</para>"
                                                     "<para>This can put a severe strain on your own as well as other people's network "
                                                     "connections, and can take up to an hour or more to complete, depending on "
                                                     "your network connection, and the number of certificates to check.</para> "
                                                     "<para>Are you sure you want to continue?</para>"),
                                              i18nc("@title:window", "X.509 Certificate Refresh"),
                                              KStandardGuiItem::cont(),
                                              KStandardGuiItem::cancel(),
                                              QStringLiteral("warn-refresh-x509-expensive"))
        == KMessageBox::Continue;
}

QStringList RefreshX509CertsCommand::arguments() const
{
    return {
        gpgSmPath(),
        QStringLiteral("-k"),
        QStringLiteral("--with-validation"),
        QStringLiteral("--force-crl-refresh"),
        QStringLiteral("--enable-crl-checks"),
    };
}

QString RefreshX509CertsCommand::errorCaption() const
{
    return i18nc("@title:window", "X.509 Certificate Refresh Error");
}

QString RefreshX509CertsCommand::successCaption() const
{
    return i18nc("@title:window", "X.509 Certificate Refresh Finished");
}

QString RefreshX509CertsCommand::crashExitMessage(const QStringList &args) const
{
    return xi18nc("@info",
                  "<para>The GpgSM process that tried to refresh X.509 certificates "
                  "ended prematurely because of an unexpected error.</para>"
                  "<para>Please check the output of <icode>%1</icode> for details.</para>",
                  args.join(QLatin1Char(' ')));
}

QString RefreshX509CertsCommand::errorExitMessage(const QStringList &args) const
{
    return xi18nc("@info",
                  "<para>An error occurred while trying to refresh X.509 certificates.</para>"
                  "<para>The output from <command>%1</command> was: <bcode>%2</bcode></para>",
                  args[0],
                  errorString());
}

QString RefreshX509CertsCommand::successMessage(const QStringList &) const
{
    return i18nc("@info", "X.509 certificates refreshed successfully.");
}

#include "moc_refreshx509certscommand.cpp"
