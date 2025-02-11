/*
    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2023 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include <config-kleopatra.h>

#include "overwritedialog.h"

#include <QFileInfo>
#include <QHBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QMimeDatabase>
#include <QPushButton>
#include <QVBoxLayout>

#include <KFileUtils>
#include <KGuiItem>
#include <KLocalizedString>
#include <KMessageBox>
#include <KSeparator>
#include <KStandardGuiItem>

using namespace Kleo;

class OverwriteDialog::Private
{
    Kleo::OverwriteDialog *q;

public:
    Private(const QString &filePath, Kleo::OverwriteDialog *qq)
        : q{qq}
        , fileInfo{filePath}
    {
    }

    void setRenameBoxText(const QString &fileName);
    void enableRenameButton(const QString &newName);
    void suggestNewNamePressed();
    QString newFileName() const;

    void renamePressed();
    void renameAllPressed();
    void skipPressed();
    void skipAllPressed();
    void appendPressed();
    void overwritePressed();
    void overwriteAllPressed();
    void cancelPressed();

    void done(Result result)
    {
        q->done(static_cast<int>(result));
    }

    QLineEdit *newNameEdit = nullptr;
    QPushButton *suggestNewNameBtn = nullptr;
    QPushButton *renameBtn = nullptr;
    QPushButton *renameAllBtn = nullptr;
    QPushButton *skipBtn = nullptr;
    QPushButton *skipAllBtn = nullptr;
    QPushButton *appendBtn = nullptr;
    QPushButton *overwriteBtn = nullptr;
    QPushButton *overwriteAllBtn = nullptr;
    QPushButton *cancelBtn = nullptr;
    QFileInfo fileInfo;
};

void OverwriteDialog::Private::setRenameBoxText(const QString &fileName)
{
    // sets the text in file name line edit box, selecting the filename (but not the extension if there is one).
    QMimeDatabase db;
    const auto extension = db.suffixForFileName(fileName);
    newNameEdit->setText(fileName);

    if (!extension.isEmpty()) {
        const int selectionLength = fileName.length() - extension.length() - 1;
        newNameEdit->setSelection(0, selectionLength);
    } else {
        newNameEdit->selectAll();
    }
}

static void enableButton(QPushButton *button)
{
    if (button) {
        button->setEnabled(true);
    }
}

static void disableButton(QPushButton *button)
{
    if (button) {
        button->setEnabled(false);
    }
}

void OverwriteDialog::Private::enableRenameButton(const QString &newName)
{
    if (!newName.isEmpty() && (newName != fileInfo.fileName())) {
        renameBtn->setEnabled(true);
        renameBtn->setDefault(true);

        disableButton(renameAllBtn);
        disableButton(appendBtn);
        disableButton(overwriteBtn);
        disableButton(overwriteAllBtn);
    } else {
        renameBtn->setEnabled(false);

        enableButton(renameAllBtn);
        enableButton(appendBtn);
        enableButton(overwriteBtn);
        enableButton(overwriteAllBtn);
    }
}

void OverwriteDialog::Private::suggestNewNamePressed()
{
    if (!newNameEdit->text().isEmpty()) {
        setRenameBoxText(KFileUtils::suggestName(QUrl::fromLocalFile(fileInfo.absolutePath()), newNameEdit->text()));
    } else {
        setRenameBoxText(KFileUtils::suggestName(QUrl::fromLocalFile(fileInfo.absolutePath()), fileInfo.fileName()));
    }
}

QString OverwriteDialog::Private::newFileName() const
{
    return fileInfo.path() + QLatin1Char{'/'} + newNameEdit->text();
}

void OverwriteDialog::Private::renamePressed()
{
    if (newNameEdit->text().isEmpty()) {
        return;
    }
    const auto fileName = newFileName();
    if (QFileInfo::exists(fileName)) {
        KMessageBox::error(q, xi18nc("@info", "The file <filename>%1</filename> already exists. Please enter a different file name.", fileName));
        return;
    }
    done(Result::Rename);
}

void OverwriteDialog::Private::renameAllPressed()
{
    done(Result::AutoRename);
}

void OverwriteDialog::Private::skipPressed()
{
    done(Result::Skip);
}

void OverwriteDialog::Private::skipAllPressed()
{
    done(Result::AutoSkip);
}

void OverwriteDialog::Private::appendPressed()
{
    done(Result::Append);
}

void OverwriteDialog::Private::overwritePressed()
{
    done(Result::Overwrite);
}

void OverwriteDialog::Private::overwriteAllPressed()
{
    done(Result::OverwriteAll);
}

void OverwriteDialog::Private::cancelPressed()
{
    done(Result::Cancel);
}

OverwriteDialog::OverwriteDialog(QWidget *parent, const QString &title, const QString &fileName, Options options)
    : QDialog{parent}
    , d{new Private{fileName, this}}
{
    setObjectName(QLatin1StringView("Kleo::OverwriteDialog"));

    setWindowTitle(title);

    auto mainLayout = new QVBoxLayout{this};
    mainLayout->addStrut(400); // makes dlg at least that wide

    mainLayout->addWidget(new QLabel{xi18nc("@info", "The file <filename>%1</filename> already exists.", fileName), this});

    if (options & AllowRename) {
        mainLayout->addSpacing(15);

        auto label = new QLabel{i18nc("@label", "Rename:"), this};
        mainLayout->addWidget(label);

        auto hbox = new QHBoxLayout;

        d->newNameEdit = new QLineEdit{this};
        label->setBuddy(d->newNameEdit);
        hbox->addWidget(d->newNameEdit);

        d->suggestNewNameBtn = new QPushButton{i18nc("@action:button", "Suggest New Name"), this};
        d->suggestNewNameBtn->setToolTip(i18nc("@info:tooltip", "Suggest a file name that does not already exist."));
        hbox->addWidget(d->suggestNewNameBtn);

        mainLayout->addLayout(hbox);
    }

    mainLayout->addWidget(new KSeparator{this});

    auto buttonLayout = new QHBoxLayout;

    if (options & AllowRename) {
        d->renameBtn = new QPushButton{i18nc("@action:button", "Rename"), this};
        d->renameBtn->setToolTip(i18nc("@info:tooltip", "Save the file with the given name."));
        d->renameBtn->setIcon(QIcon::fromTheme(QStringLiteral("edit-rename")));
        d->renameBtn->setEnabled(false);
        buttonLayout->addWidget(d->renameBtn);

        if (options & MultipleItems) {
            d->renameAllBtn = new QPushButton{i18nc("@action:button", "Rename All"), this};
            d->renameAllBtn->setIcon(d->renameBtn->icon());
            d->renameAllBtn->setToolTip(
                i18nc("@info:tooltip", "Automatically save all files that would overwrite an already existing file with a different name."));
            buttonLayout->addWidget(d->renameAllBtn);
        }
    }

    if ((options & AllowSkip) && (options & MultipleItems)) {
        d->skipBtn = new QPushButton{i18nc("@action:button", "Skip"), this};
        d->skipBtn->setIcon(QIcon::fromTheme(QStringLiteral("go-next-skip")));
        d->skipBtn->setToolTip(i18nc("@info:tooltip", "Do not write this file, skip to the next one instead."));
        buttonLayout->addWidget(d->skipBtn);

        d->skipAllBtn = new QPushButton{i18nc("@action:button", "Skip All"), this};
        d->skipAllBtn->setIcon(d->skipBtn->icon());
        d->skipAllBtn->setToolTip(i18nc("@info:tooltip", "Do not write this file and any other files that would overwrite an already existing file."));
        buttonLayout->addWidget(d->skipAllBtn);
    }

    if (options & AllowAppend) {
        d->appendBtn = new QPushButton{i18nc("@action:button", "Append"), this};
        d->appendBtn->setToolTip(i18nc("@info:tooltip", "Append the new file to the existing file."));
        d->appendBtn->setIcon(QIcon::fromTheme(QStringLiteral("document-new")));
        buttonLayout->addWidget(d->appendBtn);
    }

    d->overwriteBtn = new QPushButton{i18nc("@action:button", "Overwrite"), this};
    d->overwriteBtn->setIcon(KStandardGuiItem::overwrite().icon());
    d->overwriteBtn->setToolTip(i18nc("@info:tooltip", "Overwrite the existing file."));
    buttonLayout->addWidget(d->overwriteBtn);

    if (options & MultipleItems) {
        d->overwriteAllBtn = new QPushButton{i18nc("@action:button", "Overwrite All"), this};
        d->overwriteAllBtn->setIcon(d->overwriteBtn->icon());
        d->overwriteAllBtn->setToolTip(i18nc("@info:tooltip", "Overwrite the existing file and any other files that already exist."));
        buttonLayout->addWidget(d->overwriteAllBtn);
    }

    d->cancelBtn = new QPushButton{this};
    KGuiItem::assign(d->cancelBtn, KStandardGuiItem::cancel());
    d->cancelBtn->setDefault(true);
    buttonLayout->addWidget(d->cancelBtn);

    mainLayout->addLayout(buttonLayout);

    if (d->newNameEdit) {
        d->setRenameBoxText(d->fileInfo.fileName());
        connect(d->newNameEdit, &QLineEdit::textChanged, this, [this](const QString &text) {
            d->enableRenameButton(text);
        });
        connect(d->suggestNewNameBtn, &QAbstractButton::clicked, this, [this]() {
            d->suggestNewNamePressed();
        });
    }
    if (d->renameBtn) {
        connect(d->renameBtn, &QAbstractButton::clicked, this, [this]() {
            d->renamePressed();
        });
    }
    if (d->renameAllBtn) {
        connect(d->renameAllBtn, &QAbstractButton::clicked, this, [this]() {
            d->renameAllPressed();
        });
    }
    if (d->skipBtn) {
        connect(d->skipBtn, &QAbstractButton::clicked, this, [this]() {
            d->skipPressed();
        });
        connect(d->skipAllBtn, &QAbstractButton::clicked, this, [this]() {
            d->skipAllPressed();
        });
    }
    if (d->appendBtn) {
        connect(d->appendBtn, &QAbstractButton::clicked, this, [this]() {
            d->appendPressed();
        });
    }
    connect(d->overwriteBtn, &QAbstractButton::clicked, this, [this]() {
        d->overwritePressed();
    });
    if (d->overwriteAllBtn) {
        connect(d->overwriteAllBtn, &QAbstractButton::clicked, this, [this]() {
            d->overwriteAllPressed();
        });
    }
    connect(d->cancelBtn, &QAbstractButton::clicked, this, [this]() {
        d->cancelPressed();
    });

    if (d->newNameEdit) {
        d->newNameEdit->setFocus();
    }

    resize(sizeHint());
}

OverwriteDialog::~OverwriteDialog() = default;

QString OverwriteDialog::newFileName() const
{
    if (result() == Result::Rename) {
        return d->newFileName();
    }
    return {};
}

#include "moc_overwritedialog.cpp"
