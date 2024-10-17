/* -*- mode: c++; c-basic-offset:4 -*-
    commands/genrevokecommand.cpp

    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2017 Bundesamt für Sicherheit in der Informationstechnik
    SPDX-FileContributor: Intevation GmbH

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include <config-kleopatra.h>

#include "genrevokecommand.h"

#include <utils/applicationstate.h>

#include <Libkleo/Formatting>
#include <Libkleo/GnuPG>

#include <gpgme++/key.h>

#include <KLocalizedString>
#include <KMessageBox>

#include <QFile>
#include <QFileDialog>
#include <QProcess>
#include <QTextStream>

#include "command_p.h"
#include "kleopatra_debug.h"

using namespace Kleo;
using namespace Kleo::Commands;
using namespace GpgME;

GenRevokeCommand::GenRevokeCommand(QAbstractItemView *v, KeyListController *c)
    : GnuPGProcessCommand(v, c)
{
}

GenRevokeCommand::GenRevokeCommand(KeyListController *c)
    : GnuPGProcessCommand(c)
{
}

GenRevokeCommand::GenRevokeCommand(const Key &key)
    : GnuPGProcessCommand(key)
{
}

// Fixup the revocation certificate similar to GnuPG
void GenRevokeCommand::postSuccessHook(QWidget *parentWidget)
{
    QFile f(mOutputFileName);

    if (!f.open(QIODevice::ReadOnly)) {
        // Should never happen because in this case we would not have had a success.
        KMessageBox::error(parentWidget, QStringLiteral("Failed to access the created output file."), errorCaption());
        return;
    }
    const QString revCert = QString::fromLocal8Bit(f.readAll());
    f.close();

    if (!f.open(QIODevice::WriteOnly)) {
        KMessageBox::error(parentWidget, QStringLiteral("Failed to write to the created output file."), errorCaption());
        return;
    }

    QTextStream s(&f);

    s << i18n("This is a revocation certificate for the OpenPGP key:") << "\n\n" //
      << "             " << Formatting::prettyNameAndEMail(d->key()) << "\n" //
      << "Fingerprint: " << d->key().primaryFingerprint() << "\n\n"
      << i18n(
             "A revocation certificate is a kind of \"kill switch\" to publicly\n"
             "declare that a key shall not anymore be used.  It is not possible\n"
             "to retract such a revocation certificate once it has been published.")
      << "\n\n"
      << i18n(
             "Use it to revoke this key in case of a compromise or loss of\n"
             "the secret key.")
      << "\n\n"
      << i18n(
             "To avoid an accidental use of this file, a colon has been inserted\n"
             "before the 5 dashes below.  Remove this colon with a text editor\n"
             "before importing and publishing this revocation certificate.")
      << "\n\n:" << revCert;
    s.flush();
    qCDebug(KLEOPATRA_LOG) << "revocation certificate stored as:" << mOutputFileName;

    f.close();
    KMessageBox::information(d->parentWidgetOrView(),
                             i18nc("@info",
                                   "Certificate successfully created.<br><br>"
                                   "Note:<br>To prevent accidental import of the revocation<br>"
                                   "it is required to manually edit the certificate<br>"
                                   "before it can be imported."),
                             i18nc("@title:window", "Revocation certificate created"));
}

/* Well not much to do with GnuPGProcessCommand anymore I guess.. */
void GenRevokeCommand::doStart()
{
    auto proposedFileName = ApplicationState::lastUsedExportDirectory() + u'/' + QString::fromLatin1(d->key().primaryFingerprint()) + QLatin1StringView{".rev"};
    while (mOutputFileName.isEmpty()) {
        mOutputFileName = QFileDialog::getSaveFileName(d->parentWidgetOrView(),
                                                       i18n("Generate revocation certificate"),
                                                       proposedFileName,
                                                       QStringLiteral("%1 (*.rev)").arg(i18n("Revocation Certificates ")),
                                                       {},
                                                       QFileDialog::DontConfirmOverwrite);
        if (mOutputFileName.isEmpty()) {
            d->finished();
            return;
        }
        if (!mOutputFileName.endsWith(QLatin1StringView(".rev"))) {
            mOutputFileName += QLatin1StringView(".rev");
        }
        const QFileInfo fi{mOutputFileName};
        if (fi.exists()) {
            auto sel =
                KMessageBox::questionTwoActions(d->parentWidgetOrView(),
                                                xi18nc("@info", "The file <filename>%1</filename> already exists. Do you wish to overwrite it?", fi.fileName()),
                                                i18nc("@title:window", "Overwrite File?"),
                                                KStandardGuiItem::overwrite(),
                                                KStandardGuiItem::cancel(),
                                                {},
                                                KMessageBox::Notify | KMessageBox::Dangerous);
            if (sel == KMessageBox::ButtonCode::SecondaryAction) {
                proposedFileName = mOutputFileName;
                mOutputFileName.clear();
            }
        }
    }
    ApplicationState::setLastUsedExportDirectory(mOutputFileName);

    auto proc = process();
    // We do custom io
    disconnect(m_procReadyReadStdErrConnection);
    proc->setReadChannel(QProcess::StandardOutput);

    GnuPGProcessCommand::doStart();

    connect(proc, &QProcess::readyReadStandardOutput, this, [proc]() {
        while (proc->canReadLine()) {
            const QString line = QString::fromUtf8(proc->readLine()).trimmed();
            // Command-fd is a stable interface, while this is all kind of hacky we
            // are on a deadline :-/
            if (line == QLatin1StringView("[GNUPG:] GET_BOOL gen_revoke.okay")) {
                proc->write("y\n");
            } else if (line == QLatin1StringView("[GNUPG:] GET_LINE ask_revocation_reason.code")) {
                proc->write("0\n");
            } else if (line == QLatin1StringView("[GNUPG:] GET_LINE ask_revocation_reason.text")) {
                proc->write("\n");
            } else if (line == QLatin1StringView("[GNUPG:] GET_BOOL openfile.overwrite.okay")) {
                // We asked before
                proc->write("y\n");
            } else if (line == QLatin1StringView("[GNUPG:] GET_BOOL ask_revocation_reason.okay")) {
                proc->write("y\n");
            }
        }
    });
}

QStringList GenRevokeCommand::arguments() const
{
    const Key key = d->key();

    return {
        gpgPath(),
        QStringLiteral("--command-fd"),
        QStringLiteral("0"),
        QStringLiteral("--status-fd"),
        QStringLiteral("1"),
        QStringLiteral("-o"),
        mOutputFileName,
        QStringLiteral("--gen-revoke"),
        QLatin1StringView(key.primaryFingerprint()),
    };
}

QString GenRevokeCommand::errorCaption() const
{
    return i18nc("@title:window", "Error creating revocation certificate");
}

QString GenRevokeCommand::crashExitMessage(const QStringList &) const
{
    // We show a success message so a failure is either the user aborted
    // or a bug.
    qCDebug(KLEOPATRA_LOG) << "Crash exit of GenRevokeCommand";
    return QString();
}

QString GenRevokeCommand::errorExitMessage(const QStringList &) const
{
    // We show a success message so a failure is either the user aborted
    // or a bug.
    qCDebug(KLEOPATRA_LOG) << "Error exit of GenRevokeCommand";
    return QString();
}

#include "moc_genrevokecommand.cpp"
