// SPDX-FileCopyrightText: 2024 g10 Code GmbH
// SPDX-FileContributor: Tobias Fella <tobias.fella@gnupg.com>
// SPDX-License-Identifier: GPL-2.0-or-later

#include "debugdialog.h"

#include "settings.h"

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

// To add a new command, add a "<name>:<command>" line to kleoaptradebugcommandsrc
// <name> will be shown in the combobox, <command> will be executed

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

    auto commandLayout = new QHBoxLayout(this);

    setWindowTitle(i18nc("@title:window", "GnuPG Configuration Overview"));

    d->commandCombo = new QComboBox;
    d->commandCombo->setEditable(Settings{}.allowCustomDebugCommands());
    d->commandCombo->setInsertPolicy(QComboBox::NoInsert);

    auto commandsConfig = KSharedConfig::openConfig(QStringLiteral("kleopatradebugcommandsrc"));
    auto group = commandsConfig->group(QStringLiteral("Commands"));

    for (const auto &command : group.keyList()) {
        d->commandCombo->addItem(command, group.readEntry(command, QString()));
    }
    connect(d->commandCombo, &QComboBox::activated, this, [this]() {
        d->runCommand();
    });

    commandLayout->addWidget(d->commandCombo, 1);
    auto runButton = new QPushButton(i18nc("@action:button", "Run Command"));
    connect(runButton, &QPushButton::clicked, this, [this]() {
        d->runCommand();
    });
    commandLayout->addWidget(runButton);
    layout->addLayout(commandLayout);

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

        auto closeButton = buttonBox->addButton(QDialogButtonBox::Close);
        connect(closeButton, &QPushButton::clicked, this, &QDialog::accept);

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
    QString text;
    if (commandCombo->currentText() == commandCombo->currentData(Qt::DisplayRole).toString()) {
        text = commandCombo->currentData(Qt::UserRole).toString();
    } else {
        text = commandCombo->currentText();
    }

    auto process = new QProcess(q);
    const auto parts = text.split(QLatin1Char(' '));
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
    connect(process, &QProcess::errorOccurred, q, [this, process]() {
        outputEdit->setTextColor(KColorScheme(QPalette::Active, KColorScheme::View).foreground(KColorScheme::NegativeText).color());
        outputEdit->setText(process->errorString());
    });
    outputEdit->clear();
    process->start(parts[0], parts.mid(1));
}

DebugDialog::~DebugDialog() = default;

#include "moc_debugdialog.cpp"
