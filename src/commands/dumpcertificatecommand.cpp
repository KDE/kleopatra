/* -*- mode: c++; c-basic-offset:4 -*-
    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2008 Klarälvdalens Datakonsult AB

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include <config-kleopatra.h>

#include "dumpcertificatecommand.h"

#include "command_p.h"

#include <Libkleo/GnuPG>

#include <gpgme++/key.h>

#include <KLocalizedString>
#include <KMessageBox>
#include <KProcess>
#include <KStandardGuiItem>
#include <QPushButton>

#include <QByteArray>
#include <QFontDatabase>
#include <QHBoxLayout>
#include <QPointer>
#include <QString>
#include <QTextEdit>
#include <QTimer>
#include <QVBoxLayout>

static const int PROCESS_TERMINATE_TIMEOUT = 5000; // milliseconds

namespace
{
class DumpCertificateDialog : public QDialog
{
    Q_OBJECT
public:
    explicit DumpCertificateDialog(QWidget *parent = nullptr)
        : QDialog(parent)
        , ui(this)
    {
        resize(600, 500);
    }

Q_SIGNALS:
    void updateRequested();

public Q_SLOTS:
    void append(const QString &line)
    {
        ui.logTextWidget.append(line);
        ui.logTextWidget.ensureCursorVisible();
    }
    void clear()
    {
        ui.logTextWidget.clear();
    }

private:
    struct Ui {
        QTextEdit logTextWidget;
        QPushButton updateButton, closeButton;
        QVBoxLayout vlay;
        QHBoxLayout hlay;

        explicit Ui(DumpCertificateDialog *q)
            : logTextWidget(q)
            , updateButton(i18nc("@action:button Update the log text widget", "&Update"), q)
            , closeButton(q)
            , vlay(q)
            , hlay()
        {
            KGuiItem::assign(&closeButton, KStandardGuiItem::close());
            Q_SET_OBJECT_NAME(logTextWidget);
            Q_SET_OBJECT_NAME(updateButton);
            Q_SET_OBJECT_NAME(closeButton);
            Q_SET_OBJECT_NAME(vlay);
            Q_SET_OBJECT_NAME(hlay);

            logTextWidget.setFont(QFontDatabase::systemFont(QFontDatabase::FixedFont));
            logTextWidget.setReadOnly(true);
            logTextWidget.setWordWrapMode(QTextOption::NoWrap);

            vlay.addWidget(&logTextWidget, 1);
            vlay.addLayout(&hlay);

            hlay.addWidget(&updateButton);
            hlay.addStretch(1);
            hlay.addWidget(&closeButton);

            connect(&updateButton, &QAbstractButton::clicked, q, &DumpCertificateDialog::updateRequested);
            connect(&closeButton, &QAbstractButton::clicked, q, &QWidget::close);
        }
    } ui;
};
}

using namespace Kleo;
using namespace Kleo::Commands;

static QByteArray chomped(QByteArray ba)
{
    while (ba.endsWith('\n') || ba.endsWith('\r')) {
        ba.chop(1);
    }
    return ba;
}

class DumpCertificateCommand::Private : Command::Private
{
    friend class ::Kleo::Commands::DumpCertificateCommand;
    DumpCertificateCommand *q_func() const
    {
        return static_cast<DumpCertificateCommand *>(q);
    }

public:
    explicit Private(DumpCertificateCommand *qq, KeyListController *c);
    ~Private() override;

    QString errorString() const
    {
        return QString::fromLocal8Bit(errorBuffer);
    }

private:
    void init();
    void refreshView();

private:
    void slotProcessFinished(int, QProcess::ExitStatus);

    void slotProcessReadyReadStandardOutput()
    {
        while (process.canReadLine()) {
            const QString line = Kleo::stringFromGpgOutput(chomped(process.readLine()));
            if (dialog) {
                dialog->append(line);
            }
            outputBuffer.push_back(line);
        }
    }

    void slotProcessReadyReadStandardError()
    {
        errorBuffer += process.readAllStandardError();
    }

    void slotUpdateRequested()
    {
        if (process.state() == QProcess::NotRunning) {
            refreshView();
        }
    }

    void slotDialogDestroyed()
    {
        dialog = nullptr;
        if (process.state() != QProcess::NotRunning) {
            q->cancel();
        } else {
            finished();
        }
    }

private:
    QPointer<DumpCertificateDialog> dialog;
    KProcess process;
    QByteArray errorBuffer;
    QStringList outputBuffer;
    bool useDialog;
    bool canceled;
};

DumpCertificateCommand::Private *DumpCertificateCommand::d_func()
{
    return static_cast<Private *>(d.get());
}
const DumpCertificateCommand::Private *DumpCertificateCommand::d_func() const
{
    return static_cast<const Private *>(d.get());
}

#define d d_func()
#define q q_func()

DumpCertificateCommand::Private::Private(DumpCertificateCommand *qq, KeyListController *c)
    : Command::Private(qq, c)
    , process()
    , errorBuffer()
    , outputBuffer()
    , useDialog(true)
    , canceled(false)
{
    process.setOutputChannelMode(KProcess::SeparateChannels);
    process.setReadChannel(KProcess::StandardOutput);
}

DumpCertificateCommand::Private::~Private()
{
    if (dialog && !dialog->isVisible()) {
        delete dialog;
    }
}

DumpCertificateCommand::DumpCertificateCommand(KeyListController *c)
    : Command(new Private(this, c))
{
    d->init();
}

DumpCertificateCommand::DumpCertificateCommand(QAbstractItemView *v, KeyListController *c)
    : Command(v, new Private(this, c))
{
    d->init();
}

DumpCertificateCommand::DumpCertificateCommand(const GpgME::Key &k)
    : Command(k, new Private(this, nullptr))
{
    d->init();
}

void DumpCertificateCommand::Private::init()
{
    connect(&process, &QProcess::finished, q, [this](int exitCode, QProcess::ExitStatus status) {
        slotProcessFinished(exitCode, status);
    });
    connect(&process, &QProcess::readyReadStandardError, q, [this]() {
        slotProcessReadyReadStandardError();
    });
    connect(&process, &QProcess::readyReadStandardOutput, q, [this] {
        slotProcessReadyReadStandardOutput();
    });

    if (!key().isNull()) {
        process << gpgSmPath() << QStringLiteral("--dump-cert") << QLatin1StringView(key().primaryFingerprint());
    }
}

DumpCertificateCommand::~DumpCertificateCommand()
{
}

void DumpCertificateCommand::setUseDialog(bool use)
{
    d->useDialog = use;
}

bool DumpCertificateCommand::useDialog() const
{
    return d->useDialog;
}

QStringList DumpCertificateCommand::output() const
{
    return d->outputBuffer;
}

void DumpCertificateCommand::doStart()
{
    const std::vector<GpgME::Key> keys = d->keys();
    if (keys.size() != 1 || keys.front().protocol() != GpgME::CMS) {
        d->finished();
        return;
    }

    if (d->useDialog) {
        d->dialog = new DumpCertificateDialog;
        d->applyWindowID(d->dialog);
        d->dialog->setAttribute(Qt::WA_DeleteOnClose);
        d->dialog->setWindowTitle(i18nc("@title:window", "Certificate Dump"));

        connect(d->dialog, &DumpCertificateDialog::updateRequested, this, [this]() {
            d->slotUpdateRequested();
        });
        connect(d->dialog, &QObject::destroyed, this, [this]() {
            d->slotDialogDestroyed();
        });
    }

    d->refreshView();
}

void DumpCertificateCommand::Private::refreshView()
{
    if (dialog) {
        dialog->clear();
    }
    errorBuffer.clear();
    outputBuffer.clear();

    process.start();

    if (process.waitForStarted()) {
        if (dialog) {
            dialog->show();
        }
    } else {
        KMessageBox::error(dialog ? static_cast<QWidget *>(dialog) : parentWidgetOrView(),
                           i18n("Unable to start process gpgsm. "
                                "Please check your installation."),
                           i18n("Dump Certificate Error"));
        finished();
    }
}

void DumpCertificateCommand::doCancel()
{
    d->canceled = true;
    if (d->process.state() != QProcess::NotRunning) {
        d->process.terminate();
        QTimer::singleShot(PROCESS_TERMINATE_TIMEOUT, &d->process, &QProcess::kill);
    }
    if (d->dialog) {
        d->dialog->close();
    }
    d->dialog = nullptr;
}

void DumpCertificateCommand::Private::slotProcessFinished(int code, QProcess::ExitStatus status)
{
    if (!canceled) {
        if (status == QProcess::CrashExit)
            KMessageBox::error(dialog,
                               i18n("The GpgSM process that tried to dump the certificate "
                                    "ended prematurely because of an unexpected error. "
                                    "Please check the output of gpgsm --dump-cert %1 for details.",
                                    QLatin1StringView(key().primaryFingerprint())),
                               i18nc("@title:window", "Dump Certificate Error"));
        else if (code)
            KMessageBox::error(dialog,
                               i18n("An error occurred while trying to dump the certificate. "
                                    "The output from GpgSM was:\n%1",
                                    errorString()),
                               i18nc("@title:window", "Dump Certificate Error"));
    }
    if (!useDialog) {
        slotDialogDestroyed();
    }
}

#undef d
#undef q

#include "dumpcertificatecommand.moc"
#include "moc_dumpcertificatecommand.cpp"
