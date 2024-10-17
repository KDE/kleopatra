/*  commands/importperkeycommand.cpp

    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2017 Bundesamt für Sicherheit in der Informationstechnik
    SPDX-FileContributor: Intevation GmbH

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include <config-kleopatra.h>

#include "importpaperkeycommand.h"

#include <Libkleo/Formatting>
#include <Libkleo/GnuPG>

#include <QGpgME/ExportJob>
#include <QGpgME/ImportJob>
#include <QGpgME/Protocol>
#include <gpgme++/importresult.h>
#include <gpgme++/key.h>

#include <Libkleo/KeyCache>

#include <KLocalizedString>
#include <KMessageBox>

#include <QFileDialog>
#include <QTextStream>

#include "command_p.h"
#include "kleopatra_debug.h"

using namespace Kleo;
using namespace Kleo::Commands;
using namespace GpgME;

ImportPaperKeyCommand::ImportPaperKeyCommand(const GpgME::Key &k)
    : GnuPGProcessCommand(k)
{
}

QStringList ImportPaperKeyCommand::arguments() const
{
    const Key key = d->key();
    return {
        paperKeyInstallPath(),
        QStringLiteral("--pubring"),
        mTmpDir.path() + QStringLiteral("/pubkey.gpg"),
        QStringLiteral("--secrets"),
        mTmpDir.path() + QStringLiteral("/secrets.txt"),
        QStringLiteral("--output"),
        mTmpDir.path() + QStringLiteral("/seckey.gpg"),
    };
}

void ImportPaperKeyCommand::exportResult(const GpgME::Error &err, const QByteArray &data)
{
    if (err) {
        d->error(Formatting::errorAsString(err), errorCaption());
        d->finished();
        return;
    }
    if (!mTmpDir.isValid()) {
        // Should not happen so no i18n
        d->error(QStringLiteral("Failed to get temporary directory"), errorCaption());
        qCWarning(KLEOPATRA_LOG) << "Failed to get temporary dir";
        d->finished();
        return;
    }
    const QString fileName = mTmpDir.path() + QStringLiteral("/pubkey.gpg");
    QFile f(fileName);
    if (!f.open(QIODevice::WriteOnly)) {
        d->error(QStringLiteral("Failed to create temporary file"), errorCaption());
        qCWarning(KLEOPATRA_LOG) << "Failed to open tmp file";
        d->finished();
        return;
    }
    f.write(data);
    f.close();

    // Copy and sanitize input a bit
    QFile input(mFileName);

    if (!input.open(QIODevice::ReadOnly)) {
        d->error(xi18nc("@info", "Cannot open <filename>%1</filename> for reading.", mFileName), errorCaption());
        d->finished();
        return;
    }
    const QString outName = mTmpDir.path() + QStringLiteral("/secrets.txt");
    QFile out(outName);
    if (!out.open(QIODevice::WriteOnly)) {
        // Should not happen
        d->error(QStringLiteral("Failed to create temporary file"), errorCaption());
        qCWarning(KLEOPATRA_LOG) << "Failed to open tmp file for writing";
        d->finished();
        return;
    }

    QTextStream in(&input);
    while (!in.atEnd()) {
        // Paperkey is picky, tabs may not be part. Neither may be empty lines.
        const QString line = in.readLine().trimmed().replace(QLatin1Char('\t'), QStringLiteral("  ")) + QLatin1Char('\n');
        out.write(line.toUtf8());
    }
    input.close();
    out.close();

    GnuPGProcessCommand::doStart();
}

void ImportPaperKeyCommand::postSuccessHook(QWidget *)
{
    qCDebug(KLEOPATRA_LOG) << "Paperkey secrets restore finished successfully.";

    QFile secKey(mTmpDir.path() + QStringLiteral("/seckey.gpg"));
    if (!secKey.open(QIODevice::ReadOnly)) {
        d->error(QStringLiteral("Failed to open temporary secret"), errorCaption());
        qCWarning(KLEOPATRA_LOG) << "Failed to open tmp file";
        Q_EMIT finished();
        return;
    }
    auto data = secKey.readAll();
    secKey.close();

    auto importjob = QGpgME::openpgp()->importJob();
    auto result = importjob->exec(data);
    delete importjob;
    if (result.error()) {
        d->error(Formatting::errorAsString(result.error()), errorCaption());
        Q_EMIT finished();
        return;
    }
    if (!result.numSecretKeysImported() || (result.numSecretKeysUnchanged() == result.numSecretKeysImported())) {
        d->error(i18n("Failed to restore any secret keys."), errorCaption());
        Q_EMIT finished();
        return;
    }

    // Refresh the key after success
    KeyCache::mutableInstance()->reload(OpenPGP);
    Q_EMIT finished();
    d->information(xi18nc("@info", "Successfully restored the secret key parts from <filename>%1</filename>", mFileName));
    return;
}

void ImportPaperKeyCommand::doStart()
{
    if (paperKeyInstallPath().isNull()) {
        KMessageBox::error(d->parentWidgetOrView(),
                           xi18nc("@info",
                                  "<para><application>Kleopatra</application> uses "
                                  "<application>PaperKey</application> to import your "
                                  "text backup.</para>"
                                  "<para>Please make sure it is installed.</para>"),
                           i18nc("@title", "Failed to find PaperKey executable."));
        return;
    }

    mFileName = QFileDialog::getOpenFileName(d->parentWidgetOrView(),
                                             i18n("Select input file"),
                                             QString(),
                                             QStringLiteral("%1 (*.txt)").arg(i18n("Paper backup"))
#ifdef Q_OS_WIN
                                             /* For whatever reason at least with Qt 5.6.1 the native file dialog crashes in
                                              * my (aheinecke) Windows 10 environment when invoked here.
                                              * In other places it works, with the same arguments as in other places (e.g. import)
                                              * it works. But not here. Maybe it's our (gpg4win) build? But why did it only
                                              * crash here?
                                              *
                                              * It does not crash immediately, the program flow continues for a while before it
                                              * crashes so this is hard to debug.
                                              *
                                              * There are some reports about this
                                              * QTBUG-33119 QTBUG-41416 where different people describe "bugs" but they
                                              * describe them differently also not really reproducible.
                                              * Anyway this works for now and for such an exotic feature its good enough for now.
                                              */
                                             ,
                                             nullptr,
                                             QFileDialog::DontUseNativeDialog
#endif
    );
    if (mFileName.isEmpty()) {
        d->finished();
        return;
    }

    auto exportJob = QGpgME::openpgp()->publicKeyExportJob();
    connect(exportJob, &QGpgME::ExportJob::result, this, &ImportPaperKeyCommand::exportResult);
    exportJob->start(QStringList() << QLatin1StringView(d->key().primaryFingerprint()));
}

QString ImportPaperKeyCommand::errorCaption() const
{
    return i18nc("@title:window", "Error importing secret key");
}

QString ImportPaperKeyCommand::crashExitMessage(const QStringList &args) const
{
    return xi18nc("@info",
                  "<para>The GPG process that tried to restore the secret key "
                  "ended prematurely because of an unexpected error.</para>"
                  "<para>Please check the output of <icode>%1</icode> for details.</para>",
                  args.join(QLatin1Char(' ')));
}

QString ImportPaperKeyCommand::errorExitMessage(const QStringList &args) const
{
    return xi18nc("@info",
                  "<para>An error occurred while trying to restore the secret key.</para> "
                  "<para>The output from <command>%1</command> was:</para>"
                  "<para><message>%2</message></para>",
                  args[0],
                  errorString());
}

QString ImportPaperKeyCommand::successMessage(const QStringList &) const
{
    return QString();
}

#include "moc_importpaperkeycommand.cpp"
