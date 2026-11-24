/*
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
        d->finished();
        return;
    }
    const auto key = d->key();

    if (key.isNull()) {
        d->finished();
        return;
    }

    std::unique_ptr<QGpgME::ExportJob> exportJob{QGpgME::openpgp()->secretKeyExportJob(false)};
    connect(exportJob.get(), &QGpgME::ExportJob::result, this, [this](const GpgME::Error &err, const QByteArray &keyData) {
        if (err) {
            d->error(xi18nc("@info",
                            "<para>An error occurred during export of the secret key:</para>"
                            "<para><message>%1</message></para>",
                            Formatting::errorAsString(err)));
            d->finished();
            return;
        }
        if (err.isCanceled() || keyData.isEmpty()) {
            // if keyData is empty even though no error was reported then we assume that the user canceled the operation;
            // unfortunately, the gpgme job doesn't report a canceled operation (see T7373 and T7374)
            d->finished();
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
        d->finished();
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

    // paperkey output is 78 chars wide by default. Try to ensure a font-size where this
    // will print without wrapping. Unfortunately, to get at realiable effective sizes,
    // we first need to set margins, explicitly. We arbitrarily use 20mm margins, here, but if
    // we get larger page margins from the print dialog, those were _probably_ set explicitly,
    // and we should respect those, instead.
    const int outputWidth = 78 + 2; // wiggle room for rounding/rendering errors
    const auto minimumMargin = 20.0 * 72 / 25.4; // 20 Millimeters converted to Point
    auto printRegion = printer.pageRect(QPrinter::Point);
    const auto paperRegion = printer.paperRect(QPrinter::Point);
    printer.setPageMargins(
        QMarginsF{
            qMax(minimumMargin, printRegion.left()),
            qMax(minimumMargin, printRegion.top()),
            qMax(minimumMargin, paperRegion.right() - printRegion.right()),
            qMax(minimumMargin, paperRegion.bottom() - printRegion.bottom()),
        },
        QPageLayout::Point);
    printRegion = printer.pageRect(QPrinter::Point);

    const auto pageWidth = printRegion.width();
    auto font = QFontDatabase::systemFont(QFontDatabase::FixedFont);
    int width = QFontMetrics(font).horizontalAdvance(QString(outputWidth, QLatin1Char('X')));
    font.setPointSizeF(qMax(5.0, font.pointSizeF() * pageWidth / width));

    QTextDocument doc(QString::fromLatin1(pkProc.readAllStandardOutput()));
    doc.setPageSize(printRegion.size());
    doc.setDefaultFont(font);
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
