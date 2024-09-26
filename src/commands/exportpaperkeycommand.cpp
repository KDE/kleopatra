/* -*- mode: c++; c-basic-offset:4 -*-
    commands/exportpaperkeycommand.cpp

    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2016 Bundesamt für Sicherheit in der Informationstechnik
    SPDX-FileContributor: Intevation GmbH

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include <config-kleopatra.h>

#include "exportpaperkeycommand.h"

#include <Libkleo/Formatting>
#include <Libkleo/GnuPG>

#include <QGpgME/ExportJob>
#include <QGpgME/Protocol>

#include <gpgme++/key.h>

#include <KLocalizedString>
#include <KMessageBox>

#include <QFontDatabase>
#include <QPrintDialog>
#include <QPrinter>
#include <QTextDocument>

#include "command_p.h"
#include "kleopatra_debug.h"

using namespace Kleo;
using namespace Kleo::Commands;
using namespace GpgME;

class ExportPaperKeyCommand::Private : public Command::Private
{
    friend class ::ExportPaperKeyCommand;
    ExportPaperKeyCommand *q_func() const
    {
        return static_cast<ExportPaperKeyCommand *>(q);
    }

public:
    explicit Private(ExportPaperKeyCommand *qq, KeyListController *c = nullptr);
    ~Private() override;

    void startPaperKey(const QByteArray &data);

private:
    QProcess pkProc;
    QPointer<QGpgME::ExportJob> job;
    bool success = false;
};

ExportPaperKeyCommand::Private::Private(ExportPaperKeyCommand *qq, KeyListController *c)
    : Command::Private(qq, c)
{
}

ExportPaperKeyCommand::Private::~Private()
{
}

ExportPaperKeyCommand::Private *ExportPaperKeyCommand::d_func()
{
    return static_cast<Private *>(d.get());
}
const ExportPaperKeyCommand::Private *ExportPaperKeyCommand::d_func() const
{
    return static_cast<const Private *>(d.get());
}

#define d d_func()
#define q q_func()

ExportPaperKeyCommand::ExportPaperKeyCommand(QAbstractItemView *v, KeyListController *c)
    : Command(v, new Private(this, c))
{
}

ExportPaperKeyCommand::ExportPaperKeyCommand(const GpgME::Key &key)
    : Command(key, new Private(this))
{
}

void ExportPaperKeyCommand::doStart()
{
    if (paperKeyInstallPath().isNull()) {
        KMessageBox::error(d->parentWidgetOrView(),
                           xi18nc("@info",
                                  "<para><application>Kleopatra</application> uses "
                                  "<application>PaperKey</application> to create a minimized and"
                                  " printable version of your secret key.</para>"
                                  "<para>Please make sure it is installed.</para>"),
                           i18nc("@title", "Failed to find PaperKey executable."));
        finished();
        return;
    }
    const auto key = d->key();

    if (key.isNull()) {
        finished();
        return;
    }

    std::unique_ptr<QGpgME::ExportJob> exportJob{QGpgME::openpgp()->secretKeyExportJob(false)};
    connect(exportJob.get(), &QGpgME::ExportJob::result, this, [this](const GpgME::Error &err, const QByteArray &keyData) {
        if (err.isCanceled()) {
            finished();
            return;
        }

        if (err) {
            d->error(xi18nc("@info",
                            "<para>An error occurred during export of the secret key:</para>"
                            "<para><message>%1</message></para>",
                            Formatting::errorAsString(err)));
            finished();
            return;
        }
        d->startPaperKey(keyData);
    });

    const GpgME::Error err = exportJob->start({QLatin1StringView{key.primaryFingerprint()}});
    if (err) {
        d->error(xi18nc("@info",
                        "<para>An error occurred during export of the secret key:</para>"
                        "<para><message>%1</message></para>",
                        Formatting::errorAsString(err)));
        finished();
        return;
    }
    d->job = exportJob.release();
}

void ExportPaperKeyCommand::Private::startPaperKey(const QByteArray &data)
{
    pkProc.setProgram(paperKeyInstallPath());
    pkProc.setArguments({QStringLiteral("--output-type=base16")});

    qCDebug(KLEOPATRA_LOG) << "Starting PaperKey process.";
    pkProc.start();
    pkProc.write(data);
    pkProc.closeWriteChannel();
    pkProc.waitForFinished();

    qCDebug(KLEOPATRA_LOG) << "Paperkey export finished: " << pkProc.exitCode() << "status: " << pkProc.exitStatus();

    if (pkProc.exitStatus() == QProcess::CrashExit || pkProc.exitCode()) {
        error(xi18nc("@info",
                     "<para><application>PaperKey</application> failed with error</para>"
                     "<para><message>%1</message></para>",
                     pkProc.errorString()));
        finished();
        return;
    }

    QPrinter printer;

    const auto key = this->key();
    printer.setDocName(QStringLiteral("0x%1-sec").arg(QString::fromLatin1(key.keyID())));
    QPrintDialog printDialog(&printer, parentWidgetOrView());
    printDialog.setWindowTitle(i18nc("@title:window", "Print Secret Key"));

    if (printDialog.exec() != QDialog::Accepted) {
        qCDebug(KLEOPATRA_LOG) << "Printing aborted.";
        finished();
        return;
    }

    QTextDocument doc(QString::fromLatin1(pkProc.readAllStandardOutput()));
    doc.setDefaultFont(QFontDatabase::systemFont(QFontDatabase::FixedFont));
    doc.print(&printer);
    success = true;
    finished();
}

void ExportPaperKeyCommand::doCancel()
{
    if (d->job) {
        d->job->slotCancel();
    }
    d->job.clear();
}

bool ExportPaperKeyCommand::success() const
{
    return d->success;
}

#include "moc_exportpaperkeycommand.cpp"
