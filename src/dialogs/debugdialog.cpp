// SPDX-FileCopyrightText: 2024 g10 Code GmbH
// SPDX-FileContributor: Tobias Fella <tobias.fella@gnupg.com>
// SPDX-License-Identifier: GPL-2.0-or-later

#include "debugdialog.h"

#include <KColorScheme>
#include <KConfigGroup>
#include <KLocalizedString>
#include <KSharedConfig>

#include <QClipboard>
#include <QColor>
#include <QComboBox>
#include <QDialogButtonBox>
#include <QFileDialog>
#include <QGuiApplication>
#include <QLabel>
#include <QProcess>
#include <QPushButton>
#include <QTextEdit>
#include <QVBoxLayout>

using namespace Kleo;

struct DebugCommand {
    // If name is empty, the command itself will be shown.
    QString name;
    QString command;
};

std::vector<DebugCommand> commands = {
    {QStringLiteral("gpgconf -X"), QStringLiteral("gpgconf -X")},
};

class DebugDialog::Private
{
    friend class DebugDialog;

    Private(DebugDialog *parent);

private:
    void runCommand();
    DebugDialog *q;

    QComboBox *commandCombo;
    QTextEdit *outputEdit;
    QLabel *exitCodeLabel;
};

DebugDialog::Private::Private(DebugDialog *qq)
    : q(qq)
{
}

DebugDialog::DebugDialog(QWidget *parent)
    : QDialog(parent)
    , d(new Private(this))
{
    auto layout = new QVBoxLayout(this);

    d->commandCombo = new QComboBox;
    for (const auto &command : commands) {
        d->commandCombo->addItem(command.name.isEmpty() ? command.command : command.name, command.command);
    }
    connect(d->commandCombo, &QComboBox::currentTextChanged, this, [this]() {
        d->runCommand();
    });
    layout->addWidget(d->commandCombo);

    d->exitCodeLabel = new QLabel({});
    layout->addWidget(d->exitCodeLabel);

    d->outputEdit = new QTextEdit;
    d->outputEdit->setFontFamily(QStringLiteral("monospace"));
    d->outputEdit->setReadOnly(true);
    layout->addWidget(d->outputEdit);

    {
        auto buttonBox = new QDialogButtonBox;

        auto copyButton = buttonBox->addButton(i18nc("@action:button", "Copy to Clipboard"), QDialogButtonBox::ActionRole);
        connect(copyButton, &QPushButton::clicked, this, [this]() {
            QGuiApplication::clipboard()->setText(d->outputEdit->toPlainText());
        });
        copyButton->setIcon(QIcon::fromTheme(QStringLiteral("edit-copy")));

        auto saveButton = buttonBox->addButton(QDialogButtonBox::Save);
        connect(saveButton, &QPushButton::clicked, this, [this]() {
            QFileDialog::saveFileContent(d->outputEdit->toPlainText().toUtf8(), QStringLiteral("kleopatra_debug_%1.txt").arg(d->commandCombo->currentText()));
        });

        layout->addWidget(buttonBox);
    }

    KConfigGroup cfgGroup(KSharedConfig::openStateConfig(), QStringLiteral("DebugDialog"));
    const auto size = cfgGroup.readEntry("Size", QSize{640, 480});
    if (size.isValid()) {
        resize(size);
    }

    d->runCommand();
}

void DebugDialog::Private::runCommand()
{
    auto process = new QProcess(q);
    const auto parts = commandCombo->currentData().toString().split(QLatin1Char(' '));
    process->start(parts[0], parts.mid(1));
    connect(process, &QProcess::finished, q, [this, process]() {
        exitCodeLabel->setText(i18nc("@info", "Exit code: %1", process->exitCode()));
        if (process->exitCode() == 0) {
            outputEdit->setTextColor(KColorScheme(QPalette::Current, KColorScheme::View).foreground(KColorScheme::NormalText).color());
            outputEdit->setText(QString::fromUtf8(process->readAllStandardOutput()));
        } else {
            auto errorText = QString::fromUtf8(process->readAllStandardError());
            if (errorText.isEmpty()) {
                errorText = process->errorString();
            }
            outputEdit->setTextColor(KColorScheme(QPalette::Active, KColorScheme::View).foreground(KColorScheme::NegativeText).color());
            outputEdit->setText(errorText);
        }
        process->deleteLater();
    });
}

DebugDialog::~DebugDialog() = default;
