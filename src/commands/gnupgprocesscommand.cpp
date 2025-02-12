/*
    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2008 Klarälvdalens Datakonsult AB

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include <config-kleopatra.h>

#include "gnupgprocesscommand.h"

#include "command_p.h"

#include <Libkleo/GnuPG>

#include "kleopatra_debug.h"
#include <KLocalizedString>
#include <KWindowSystem>

#include <QByteArray>
#include <QDialog>
#include <QDialogButtonBox>
#include <QPointer>
#include <QProcess>
#include <QPushButton>
#include <QString>
#include <QTextEdit>
#include <QTimer>
#include <QVBoxLayout>

static const int PROCESS_TERMINATE_TIMEOUT = 5000; // milliseconds

using namespace Kleo;
using namespace Kleo::Commands;

namespace
{

class OutputDialog : public QDialog
{
    Q_OBJECT
public:
    explicit OutputDialog(QWidget *parent = nullptr)
        : QDialog(parent)
        , vlay(this)
        , logTextWidget(this)
        , buttonBox(QDialogButtonBox::Cancel | QDialogButtonBox::Close, Qt::Horizontal, this)
    {
        Q_SET_OBJECT_NAME(vlay);
        Q_SET_OBJECT_NAME(logTextWidget);
        Q_SET_OBJECT_NAME(buttonBox);

        logTextWidget.setReadOnly(true);

        vlay.addWidget(&logTextWidget, 1);
        vlay.addWidget(&buttonBox);

        connect(closeButton(), &QAbstractButton::clicked, this, &QWidget::close);
        connect(cancelButton(), &QAbstractButton::clicked, this, &OutputDialog::slotCancelClicked);

        resize(600, 500);
    }

Q_SIGNALS:
    void cancelRequested();

public Q_SLOTS:
    void message(const QString &s)
    {
        logTextWidget.append(s);
        logTextWidget.ensureCursorVisible();
    }
    void setComplete(bool complete)
    {
        cancelButton()->setVisible(!complete);
    }

private Q_SLOTS:
    void slotCancelClicked()
    {
        cancelButton()->hide();
        Q_EMIT cancelRequested();
    }

private:
    QAbstractButton *closeButton() const
    {
        return buttonBox.button(QDialogButtonBox::Close);
    }
    QAbstractButton *cancelButton() const
    {
        return buttonBox.button(QDialogButtonBox::Cancel);
    }

private:
    QVBoxLayout vlay;
    QTextEdit logTextWidget;
    QDialogButtonBox buttonBox;
};

}

class GnuPGProcessCommand::Private : Command::Private
{
    friend class ::Kleo::Commands::GnuPGProcessCommand;
    GnuPGProcessCommand *q_func() const
    {
        return static_cast<GnuPGProcessCommand *>(q);
    }

public:
    explicit Private(GnuPGProcessCommand *qq, KeyListController *c);
    ~Private() override;

private:
    void init();
    void ensureDialogCreated()
    {
        if (!showsOutputWindow) {
            return;
        }
        if (!dialog) {
            dialog = new OutputDialog;
            dialog->setAttribute(Qt::WA_DeleteOnClose);
            applyWindowID(dialog);
            connect(dialog.data(), &OutputDialog::cancelRequested, q, &Command::cancel);
            dialog->setWindowTitle(i18nc("@title:window", "Subprocess Diagnostics"));
        }
    }
    void ensureDialogVisible()
    {
        if (!showsOutputWindow) {
            return;
        }
        ensureDialogCreated();
        if (dialog->isVisible()) {
            dialog->raise();
        } else {
            dialog->show();
        }
    }
    void message(const QString &msg)
    {
        if (dialog) {
            dialog->message(msg);
        } else {
            qCDebug(KLEOPATRA_LOG) << msg;
        }
    }

private:
    void slotProcessFinished(int, QProcess::ExitStatus);
    void slotProcessReadyReadStandardError();

private:
    QProcess process;
    QPointer<OutputDialog> dialog;
    QStringList arguments;
    QByteArray errorBuffer;
    bool ignoresSuccessOrFailure;
    bool showsOutputWindow;
    bool canceled;
    bool success = false;
    bool interactive = true;
};

GnuPGProcessCommand::Private *GnuPGProcessCommand::d_func()
{
    return static_cast<Private *>(d.get());
}
const GnuPGProcessCommand::Private *GnuPGProcessCommand::d_func() const
{
    return static_cast<const Private *>(d.get());
}

#define d d_func()
#define q q_func()

GnuPGProcessCommand::Private::Private(GnuPGProcessCommand *qq, KeyListController *c)
    : Command::Private(qq, c)
    , process()
    , dialog()
    , errorBuffer()
    , ignoresSuccessOrFailure(false)
    , showsOutputWindow(false)
    , canceled(false)
{
    process.setReadChannel(QProcess::StandardError);
}

GnuPGProcessCommand::Private::~Private()
{
}

GnuPGProcessCommand::GnuPGProcessCommand(KeyListController *c)
    : Command(new Private(this, c))
{
    d->init();
}

GnuPGProcessCommand::GnuPGProcessCommand(QAbstractItemView *v, KeyListController *c)
    : Command(v, new Private(this, c))
{
    d->init();
}

GnuPGProcessCommand::GnuPGProcessCommand(const GpgME::Key &key)
    : Command(key, new Private(this, nullptr))
{
    d->init();
}

GnuPGProcessCommand::GnuPGProcessCommand(const std::vector<GpgME::Key> &keys)
    : Command(keys, new Private(this, nullptr))
{
    d->init();
}

void GnuPGProcessCommand::Private::init()
{
    connect(&process, &QProcess::finished, q, [this](int exitCode, QProcess::ExitStatus status) {
        slotProcessFinished(exitCode, status);
    });
    q->m_procReadyReadStdErrConnection = connect(&process, &QProcess::readyReadStandardError, q, [this]() {
        slotProcessReadyReadStandardError();
    });
}

GnuPGProcessCommand::~GnuPGProcessCommand()
{
}

QDialog *GnuPGProcessCommand::dialog() const
{
    return d->dialog;
}

bool GnuPGProcessCommand::preStartHook(QWidget *) const
{
    return true;
}

void GnuPGProcessCommand::postSuccessHook(QWidget *)
{
}

void GnuPGProcessCommand::doStart()
{
    if (!preStartHook(d->parentWidgetOrView())) {
        d->finished();
        return;
    }

    d->arguments = arguments();

    d->process.setProgram(d->arguments.takeFirst());

    d->process.setArguments(d->arguments);

    // Historically code using this expects arguments first to be the program.
    d->arguments.prepend(d->process.program());

    d->process.start();

    if (!d->process.waitForStarted()) {
        d->error(i18n("Unable to start process %1. "
                      "Please check your installation.",
                      d->arguments[0]),
                 errorCaption());
        d->finished();
    } else {
        d->ensureDialogVisible();
        d->message(i18n("Starting %1...", d->arguments.join(QLatin1Char(' '))));
    }
}

void GnuPGProcessCommand::doCancel()
{
    d->canceled = true;
    if (d->process.state() != QProcess::NotRunning) {
        d->process.terminate();
        QTimer::singleShot(PROCESS_TERMINATE_TIMEOUT, &d->process, &QProcess::kill);
    }
}

void GnuPGProcessCommand::Private::slotProcessFinished(int code, QProcess::ExitStatus status)
{
    if (!canceled) {
        if (status == QProcess::CrashExit) {
            success = false;
            const QString msg = q->crashExitMessage(arguments);
            if (!msg.isEmpty()) {
                error(msg, q->errorCaption());
            }
        } else if (ignoresSuccessOrFailure) {
            success = true;
            if (dialog && interactive) {
                message(i18n("Process finished"));
            } else {
                ;
            }
        } else if (code) {
            success = false;
            const QString msg = q->errorExitMessage(arguments);
            if (!msg.isEmpty()) {
                error(q->errorExitMessage(arguments), q->errorCaption());
            }
        } else {
            success = true;
            q->postSuccessHook(parentWidgetOrView());
            const QString successMessage = q->successMessage(arguments);
            if (!successMessage.isNull() && interactive) {
                if (dialog) {
                    message(successMessage);
                } else {
                    information(successMessage, q->successCaption());
                }
            }
        }
    }

    if (dialog) {
        dialog->setComplete(true);
    }
    finished();
}

void GnuPGProcessCommand::Private::slotProcessReadyReadStandardError()
{
    auto ba = process.readAllStandardError();
    errorBuffer += ba;
    while (ba.endsWith('\n') || ba.endsWith('\r')) {
        ba.chop(1);
    }
    message(Kleo::stringFromGpgOutput(ba));
}

QString GnuPGProcessCommand::errorString() const
{
    return Kleo::stringFromGpgOutput(d->errorBuffer);
}

void GnuPGProcessCommand::setIgnoresSuccessOrFailure(bool ignores)
{
    d->ignoresSuccessOrFailure = ignores;
}

bool GnuPGProcessCommand::ignoresSuccessOrFailure() const
{
    return d->ignoresSuccessOrFailure;
}

void GnuPGProcessCommand::setShowsOutputWindow(bool show)
{
    if (show == d->showsOutputWindow) {
        return;
    }
    d->showsOutputWindow = show;
    if (show) {
        d->ensureDialogCreated();
    } else {
        if (d->dialog) {
            d->dialog->deleteLater();
        }
        d->dialog = nullptr;
    }
}

bool GnuPGProcessCommand::showsOutputWindow() const
{
    return d->showsOutputWindow;
}

QProcess *GnuPGProcessCommand::process()
{
    return &d->process;
}

QString GnuPGProcessCommand::successCaption() const
{
    return QString();
}

QString GnuPGProcessCommand::successMessage(const QStringList &args) const
{
    Q_UNUSED(args)
    return QString();
}

bool GnuPGProcessCommand::success() const
{
    return d->success;
}

void GnuPGProcessCommand::setInteractive(bool interactive)
{
    d->interactive = interactive;
}

bool GnuPGProcessCommand::interactive() const
{
    return d->interactive;
}

#undef d
#undef q

#include "gnupgprocesscommand.moc"
#include "moc_gnupgprocesscommand.cpp"
