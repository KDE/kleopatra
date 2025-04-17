// SPDX-FileCopyrightText: 2024 g10 Code GmbH
// SPDX-FileContributor: Tobias Fella <tobias.fella@gnupg.com>
// SPDX-License-Identifier: GPL-2.0-or-later

#include "debugdialog.h"

#include "kleopatra_debug.h"

#include "labelledwidget.h"
#include "settings.h"

#include <KColorScheme>
#include <KConfigGroup>
#include <KLocalizedString>
#include <KSharedConfig>

#include <QClipboard>
#include <QColor>
#include <QComboBox>
#include <QCompleter>
#include <QDialogButtonBox>
#include <QFileDialog>
#include <QGuiApplication>
#include <QLabel>
#include <QLineEdit>
#include <QProcess>
#include <QPushButton>
#include <QTextEdit>
#include <QVBoxLayout>

using namespace Kleo;

using namespace Qt::Literals::StringLiterals;

// To add a new command, add a "<index>;<name>=<command>" line to kleopatradebugcommandsrc
// <name> will be shown in the combobox, <command> will be executed.
// The commands will be sorted by <index>

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

    auto commandLayout = new QHBoxLayout;

    setWindowTitle(i18nc("@title:window", "GnuPG Configuration Overview"));

    d->commandCombo = new QComboBox;
    d->commandCombo->setEditable(Settings{}.allowCustomDebugCommands());
    d->commandCombo->setInsertPolicy(QComboBox::InsertAtBottom);
    if (auto completer = d->commandCombo->completer()) {
        completer->setCaseSensitivity(Qt::CaseSensitive);
        completer->setCompletionMode(QCompleter::PopupCompletion);
    }

    auto commandsConfig = KSharedConfig::openConfig(QStringLiteral("kleopatradebugcommandsrc"));
    auto group = commandsConfig->group(QStringLiteral("DebugCommands"));

    struct Command {
        int index;
        QString name;
        QString command;
    };

    QList<Command> commands;
    for (const auto &key : group.keyList()) {
        const auto split = key.split(u';');
        if (split.size() != 2) {
            qCWarning(KLEOPATRA_LOG) << "Invalid command" << key;
            continue;
        }
        commands.append({split[0].toInt(), split[1], group.readEntry(key, QString())});
    }

    std::ranges::sort(commands, {}, &Command::index);

    for (const auto &command : commands) {
        d->commandCombo->addItem(command.name, command.command);
    }
    connect(d->commandCombo, &QComboBox::activated, this, [this]() {
        d->runCommand();
    });

    commandLayout->addWidget(d->commandCombo, 1);
    auto runButton = new QPushButton(i18nc("@action:button", "Run Command"));
    runButton->setAutoDefault(false);
    connect(runButton, &QPushButton::clicked, this, [this]() {
        // This is roughly a manual implementation of the InsertAtBottom behavior of the combobox. The combobox only only inserts an item
        // when pressing Enter, which isn't very discoverable, hence the button.
        if (const auto index = d->commandCombo->findData(QVariant::fromValue(d->commandCombo->currentText()), Qt::UserRole); index != -1) {
            d->commandCombo->setCurrentIndex(index);
        } else if (const auto index = d->commandCombo->findData(QVariant::fromValue(d->commandCombo->currentText()), Qt::DisplayRole); index != -1) {
            d->commandCombo->setCurrentIndex(index);
        } else {
            d->commandCombo->addItem(d->commandCombo->currentText(), d->commandCombo->currentText());
            d->commandCombo->setCurrentIndex(d->commandCombo->count() - 1);
        }
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

    auto searchLayout = new QHBoxLayout;

    auto searchField = new LabelledWidget<QLineEdit>();
    searchField->createWidgets(this);
    searchField->label()->setText(i18nc("@label", "Search:"));
    searchField->widget()->setToolTip(i18nc("@info:tooltip", "Search in output"));
    searchField->widget()->setPlaceholderText(i18nc("@info:placeholder", "Enter search term"));
    connect(searchField->widget(), &QLineEdit::textChanged, this, [this, searchField]() {
        d->outputEdit->moveCursor(QTextCursor::Start);
        d->outputEdit->find(searchField->widget()->text());
    });

    auto searchNext = [this, searchField]() {
        if (!d->outputEdit->find(searchField->widget()->text())) {
            d->outputEdit->moveCursor(QTextCursor::Start);
            d->outputEdit->find(searchField->widget()->text());
        }
    };

    connect(searchField->widget(), &QLineEdit::returnPressed, this, searchNext);
    searchLayout->addWidget(searchField->label());
    searchLayout->addWidget(searchField->widget());

    auto nextButton = new QPushButton(QIcon::fromTheme(QStringLiteral("arrow-down")), {});
    nextButton->setToolTip(i18nc("@info:tooltip", "Jump to next match"));
    nextButton->setAccessibleName(i18nc("@action:button", "Find Next"));
    connect(nextButton, &QPushButton::clicked, this, searchNext);

    searchLayout->addWidget(nextButton);
    auto previousButton = new QPushButton(QIcon::fromTheme(QStringLiteral("arrow-up")), {});
    previousButton->setToolTip(i18nc("@info:tooltip", "Jump to previous match"));
    previousButton->setAccessibleName(i18nc("@action:button", "Find Previous"));
    connect(previousButton, &QPushButton::clicked, this, [this, searchField]() {
        if (!d->outputEdit->find(searchField->widget()->text(), QTextDocument::FindBackward)) {
            d->outputEdit->moveCursor(QTextCursor::End);
            d->outputEdit->find(searchField->widget()->text(), QTextDocument::FindBackward);
        }
    });
    searchLayout->addWidget(previousButton);

    layout->addLayout(searchLayout);
    {
        auto buttonBox = new QDialogButtonBox;

        auto copyButton = buttonBox->addButton(i18nc("@action:button", "Copy to Clipboard"), QDialogButtonBox::ActionRole);
        connect(copyButton, &QPushButton::clicked, this, [this]() {
            QGuiApplication::clipboard()->setText(d->outputEdit->toPlainText());
        });
        copyButton->setIcon(QIcon::fromTheme(QStringLiteral("edit-copy")));

        auto saveButton = buttonBox->addButton(i18nc("@action:button", "Save to File"), QDialogButtonBox::ActionRole);
        connect(saveButton, &QPushButton::clicked, this, [this]() {
            auto text = d->commandCombo->currentText();
            text.replace(QRegularExpression(u"[^a-zA-Z0-9-]"_s), u"_"_s);
            QFileDialog::saveFileContent(d->outputEdit->toPlainText().toUtf8(), QStringLiteral("kleopatra_debug_%1.txt").arg(text));
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
    text = commandCombo->currentData(Qt::UserRole).toString();
    if (text.isEmpty()) {
        text = commandCombo->currentData(Qt::DisplayRole).toString();
    }

    auto process = new QProcess(q);
    const auto parts = text.split(QLatin1Char(' '));
    exitCodeLabel->setText({});
    connect(process, &QProcess::finished, outputEdit, [this, process]() {
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
    connect(process, &QProcess::errorOccurred, outputEdit, [this, process]() {
        outputEdit->setTextColor(KColorScheme(QPalette::Active, KColorScheme::View).foreground(KColorScheme::NegativeText).color());
        outputEdit->setText(process->errorString());
    });
    outputEdit->clear();
    process->setStandardInputFile(QProcess::nullDevice());
    process->start(parts[0], parts.mid(1));
}

DebugDialog::~DebugDialog() = default;

#include "moc_debugdialog.cpp"
