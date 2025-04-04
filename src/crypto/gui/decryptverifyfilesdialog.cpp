/*
    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2007 Klarälvdalens Datakonsult AB
    SPDX-FileCopyrightText: 2016 Bundesamt für Sicherheit in der Informationstechnik
    SPDX-FileContributor: Intevation GmbH

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include "decryptverifyfilesdialog.h"

#include "kleopatra_debug.h"

#include "crypto/decryptverifytask.h"
#include "crypto/gui/resultlistwidget.h"
#include "crypto/gui/resultpage.h"
#include "crypto/taskcollection.h"
#include "utils/fileutils.h"
#include "utils/path-helper.h"

#include <Libkleo/FileNameRequester>

#include <QLabel>
#include <QProgressBar>
#include <QPushButton>
#include <QVBoxLayout>
#include <QWindow>

#include <KConfigGroup>
#include <KLocalizedContext>
#include <KLocalizedString>
#include <KMessageBox>
#include <KSharedConfig>
#include <MimeTreeParserWidgets/MessageViewerDialog>

using namespace Kleo;
using namespace Kleo::Crypto;
using namespace Kleo::Crypto::Gui;
using namespace MimeTreeParser::Widgets;

DecryptVerifyFilesDialog::DecryptVerifyFilesDialog(const std::shared_ptr<TaskCollection> &coll, QWidget *parent)
    : QDialog(parent)
    , m_tasks(coll)
    , m_buttonBox(new QDialogButtonBox)
{
    readConfig();
    auto vLay = new QVBoxLayout(this);
    auto labels = new QWidget;
    auto outputLayout = new QHBoxLayout;

    m_outputLocationFNR = new FileNameRequester;
    m_outputLocationFNR->setButtonHint(i18nc("@info:tooltip", "Choose output folder"));
    auto outLabel = new QLabel(i18nc("@label:textbox", "&Output folder:"));
    outLabel->setBuddy(m_outputLocationFNR);
    outputLayout->addWidget(outLabel);
    outputLayout->addWidget(m_outputLocationFNR);
    m_outputLocationFNR->setFilter(QDir::Dirs);

    vLay->addLayout(outputLayout);

    m_progressLabelLayout = new QVBoxLayout(labels);
    vLay->addWidget(labels);
    m_progressBar = new QProgressBar;
    vLay->addWidget(m_progressBar);
    m_resultList = new ResultListWidget;
    connect(m_resultList, &ResultListWidget::showButtonClicked, this, &DecryptVerifyFilesDialog::showContent);
    vLay->addWidget(m_resultList);

    m_tasks = coll;
    Q_ASSERT(m_tasks);
    m_resultList->setTaskCollection(coll);
    connect(m_tasks.get(), &TaskCollection::progress, this, &DecryptVerifyFilesDialog::progress);
    connect(m_tasks.get(), &TaskCollection::done, this, &DecryptVerifyFilesDialog::allDone);
    connect(m_tasks.get(), &TaskCollection::started, this, &DecryptVerifyFilesDialog::started);

    connect(m_buttonBox, &QDialogButtonBox::rejected, this, &QDialog::reject);
    connect(m_buttonBox, &QDialogButtonBox::clicked, this, &DecryptVerifyFilesDialog::btnClicked);

    layout()->addWidget(m_buttonBox);

    bool hasOutputs = false;
    for (const auto &t : coll->tasks()) {
        if (!qobject_cast<VerifyDetachedTask *>(t.get())) {
            hasOutputs = true;
            break;
        }
    }
    if (hasOutputs) {
        setWindowTitle(i18nc("@title:window", "Decrypt/Verify Files"));
        m_saveButton = QDialogButtonBox::SaveAll;
        m_buttonBox->addButton(QDialogButtonBox::Discard);
        connect(m_buttonBox, &QDialogButtonBox::accepted, this, &DecryptVerifyFilesDialog::checkAccept);
    } else {
        outLabel->setVisible(false);
        m_outputLocationFNR->setVisible(false);
        setWindowTitle(i18nc("@title:window", "Verify Files"));
        m_buttonBox->addButton(QDialogButtonBox::Close);
        connect(m_buttonBox, &QDialogButtonBox::accepted, this, &QDialog::accept);
    }
    if (m_saveButton) {
        m_buttonBox->addButton(m_saveButton);
        m_buttonBox->button(m_saveButton)->setEnabled(false);
    }

    m_progressLabel = new QLabel;
    m_progressLabel->setTextFormat(Qt::RichText);
    m_progressLabel->setWordWrap(true);
    m_progressLabelLayout->addWidget(m_progressLabel);
}

DecryptVerifyFilesDialog::~DecryptVerifyFilesDialog()
{
    qCDebug(KLEOPATRA_LOG);
    writeConfig();
}

void DecryptVerifyFilesDialog::allDone()
{
    qCDebug(KLEOPATRA_LOG) << "All done";
    Q_ASSERT(m_tasks);
    m_progressBar->setRange(0, 100);
    m_progressBar->setValue(100);
    m_progressBar->setVisible(false);

    m_progressLabel->setVisible(false);

    if (m_tasks->allTasksHaveErrors()) {
        return;
    }
    if (m_saveButton != QDialogButtonBox::NoButton) {
        m_buttonBox->button(m_saveButton)->setEnabled(true);
    } else {
        m_buttonBox->removeButton(m_buttonBox->button(QDialogButtonBox::Close));
        m_buttonBox->addButton(QDialogButtonBox::Ok);
    }
}

void DecryptVerifyFilesDialog::started(const std::shared_ptr<Task> &task)
{
    Q_ASSERT(task);
    m_progressLabel->setText(task->label());
    if (m_saveButton != QDialogButtonBox::NoButton) {
        m_buttonBox->button(m_saveButton)->setEnabled(false);
    } else if (m_buttonBox->button(QDialogButtonBox::Ok)) {
        m_buttonBox->removeButton(m_buttonBox->button(QDialogButtonBox::Ok));
        m_buttonBox->addButton(QDialogButtonBox::Close);
    }
}

void DecryptVerifyFilesDialog::progress(int progress, int total)
{
    Q_ASSERT(progress >= 0);
    Q_ASSERT(total >= 0);
    m_progressBar->setRange(0, total);
    m_progressBar->setValue(progress);
}

void DecryptVerifyFilesDialog::setOutputLocation(const QString &dir)
{
    m_outputLocationFNR->setFileName(dir);
}

QString DecryptVerifyFilesDialog::outputLocation() const
{
    return m_outputLocationFNR->fileName();
}

void DecryptVerifyFilesDialog::btnClicked(QAbstractButton *btn)
{
    if (m_buttonBox->buttonRole(btn) == QDialogButtonBox::DestructiveRole) {
        close();
    }
}

void DecryptVerifyFilesDialog::checkAccept()
{
    if (Kleo::ensureOutputDirectoryExists(outputLocation(), this)) {
        accept();
    }
}

void DecryptVerifyFilesDialog::readConfig()
{
    KConfigGroup dialog(KSharedConfig::openStateConfig(), QStringLiteral("DecryptVerifyFilesDialog"));
    const QSize size = dialog.readEntry("Size", QSize(640, 480));
    if (size.isValid()) {
        resize(size);
    }
}

void DecryptVerifyFilesDialog::writeConfig()
{
    KConfigGroup dialog(KSharedConfig::openStateConfig(), QStringLiteral("DecryptVerifyFilesDialog"));
    dialog.writeEntry("Size", size());
    dialog.sync();
}

void DecryptVerifyFilesDialog::showContent(const std::shared_ptr<const Task::Result> &result)
{
    if (auto decryptVerifyResult = std::dynamic_pointer_cast<const DecryptVerifyResult>(result)) {
        MessageViewerDialog dialog(decryptVerifyResult->fileName());
        dialog.exec();
    }
}

#include "moc_decryptverifyfilesdialog.cpp"
