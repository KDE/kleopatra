// SPDX-FileCopyrightText: 2024 g10 Code GmbH
// SPDX-FileContributor: Tobias Fella <tobias.fella@gnupg.com>
// SPDX-License-Identifier: GPL-2.0-or-later

#include "debugviewdialog.h"

#include <KLocalizedString>

#include <QClipboard>
#include <QComboBox>
#include <QDialogButtonBox>
#include <QGuiApplication>
#include <QProcess>
#include <QPushButton>
#include <QTextEdit>
#include <QVBoxLayout>

using namespace Kleo::Dialogs;

class DebugViewDialog::Private
{
    friend class ::Kleo::Dialogs::DebugViewDialog;
    DebugViewDialog *const q;

public:
    Private(DebugViewDialog *qq)
        : q{qq}
        , ui{qq}
    {
    }

    void loadCommands()
    {
        QStringList commands = {
            QStringLiteral("ls"),
            QStringLiteral("uname"),
            QStringLiteral("uname -r"),
            QStringLiteral("whoami"),
            QStringLiteral("ps -a"),
        };
        for (const auto &command : commands) {
            ui.commandsCombo->addItem(command);
        }
    }
    void runCommand()
    {
        auto process = new QProcess();
        auto command = ui.commandsCombo->currentText().split(QLatin1Char(' '));
        process->start(command[0], command.mid(1));
        connect(process, &QProcess::finished, q, [process, this]() {
            if (process->exitCode() != 0) {
                ui.result->setText(i18nc("@info", "Error executing command: %1\n%2", process->exitCode(), QString::fromUtf8(process->readAllStandardError())));
            } else {
                ui.result->setText(QString::fromUtf8(process->readAllStandardOutput()));
            }
            q->resize(ui.layout->sizeHint());
        });
    }

private:
    struct UI {
        QVBoxLayout *layout;
        QComboBox *commandsCombo;
        QTextEdit *result;
        QDialogButtonBox *buttons;
        QPushButton *closeButton;
        QPushButton *copyButton;

        explicit UI(DebugViewDialog *qq)
        {
            layout = new QVBoxLayout;
            qq->setLayout(layout);
            commandsCombo = new QComboBox;
            layout->addWidget(commandsCombo);

            result = new QTextEdit;
            result->setReadOnly(true);
            result->setFontFamily(QStringLiteral("monospace"));
            layout->addWidget(result);

            buttons = new QDialogButtonBox;
            closeButton = buttons->addButton(QDialogButtonBox::Close);
            copyButton = new QPushButton(QIcon::fromTheme(QStringLiteral("edit-copy")), i18nc("@action:button", "Copy Text"));
            buttons->addButton(copyButton, QDialogButtonBox::ActionRole);

            layout->addWidget(buttons);
        }
    } ui;
};

DebugViewDialog::DebugViewDialog(QWidget *parent)
    : QDialog(parent)
    , d(new Private(this))
{
    setWindowTitle(i18nc("@title:window", "Debug View"));
    d->loadCommands();
    d->runCommand();
    connect(d->ui.commandsCombo, &QComboBox::currentIndexChanged, this, [this]() {
        d->runCommand();
    });
    connect(d->ui.closeButton, &QPushButton::clicked, this, [this]() {
        close();
    });
    connect(d->ui.copyButton, &QPushButton::clicked, this, [this]() {
        QGuiApplication::clipboard()->setText(d->ui.result->toPlainText());
    });
}

#include "moc_debugviewdialog.cpp"
