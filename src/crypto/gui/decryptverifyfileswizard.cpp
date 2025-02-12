/*
    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2007 Klarälvdalens Datakonsult AB

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include <config-kleopatra.h>

#include "decryptverifyfileswizard.h"

#include "decryptverifyoperationwidget.h"
#include "utils/fileutils.h"

#include <crypto/gui/resultpage.h>
#include <crypto/gui/wizardpage.h>

#include <crypto/task.h>
#include <crypto/taskcollection.h>

#include <utils/kleo_assert.h>

#include <Libkleo/FileNameRequester>
#include <Libkleo/Stl_Util>

#include <KAdjustingScrollArea>
#include <KGuiItem>
#include <KLocalizedString>

#include <QBoxLayout>
#include <QCheckBox>
#include <QLabel>
#include <QTimer>
#include <QTreeView>

#include <vector>

using namespace Kleo;
using namespace Kleo::Crypto;
using namespace Kleo::Crypto::Gui;

namespace
{

class HLine : public QFrame
{
    Q_OBJECT
public:
    explicit HLine(QWidget *p = nullptr, Qt::WindowFlags f = {})
        : QFrame(p, f)
    {
        setFrameStyle(static_cast<int>(QFrame::HLine) | static_cast<int>(QFrame::Sunken));
    }
};

class OperationsWidget : public WizardPage
{
    Q_OBJECT
public:
    explicit OperationsWidget(QWidget *p = nullptr);
    ~OperationsWidget() override;

    void setOutputDirectory(const QString &dir)
    {
        m_ui.outputDirectoryFNR.setFileName(dir);
    }

    QString outputDirectory() const
    {
        return m_ui.outputDirectoryFNR.fileName();
    }

    bool useOutputDirectory() const
    {
        return m_ui.useOutputDirectoryCB.isChecked();
    }

    void ensureIndexAvailable(unsigned int idx);

    DecryptVerifyOperationWidget *widget(unsigned int idx)
    {
        return m_widgets.at(idx);
    }

    bool isComplete() const override
    {
        return std::all_of(m_widgets.cbegin(), m_widgets.cend(), [](const auto &w) {
            switch (w->mode()) {
            case DecryptVerifyOperationWidget::VerifyDetachedWithSignature:
            case DecryptVerifyOperationWidget::VerifyDetachedWithSignedData: {
                const QString sigFileName = w->inputFileName();
                const QString dataFileName = w->signedDataFileName();
                return !sigFileName.isEmpty() && !dataFileName.isEmpty() && QFile::exists(sigFileName) && QFile::exists(dataFileName);
            }
            case DecryptVerifyOperationWidget::DecryptVerifyOpaque:;
            }
            return true;
        });
    }

    bool onNext() override
    {
        return Kleo::ensureOutputDirectoryExists(outputDirectory(), this);
    }

private:
    std::vector<DecryptVerifyOperationWidget *> m_widgets;

    struct UI {
        QCheckBox useOutputDirectoryCB;
        QLabel outputDirectoryLB;
        FileNameRequester outputDirectoryFNR;
        KAdjustingScrollArea scrollArea;
        QVBoxLayout vlay;
        QHBoxLayout hlay;

        explicit UI(OperationsWidget *q);
    } m_ui;
};
}

class DecryptVerifyFilesWizard::Private
{
    friend class ::Kleo::Crypto::Gui::DecryptVerifyFilesWizard;
    DecryptVerifyFilesWizard *const q;

public:
    Private(DecryptVerifyFilesWizard *qq);
    ~Private();

    void ensureIndexAvailable(unsigned int idx)
    {
        operationsPage.ensureIndexAvailable(idx);
    }

private:
    OperationsWidget operationsPage;
    Gui::ResultPage resultPage;
};

DecryptVerifyFilesWizard::DecryptVerifyFilesWizard(QWidget *p, Qt::WindowFlags f)
    : Wizard(p, f)
    , d(new Private(this))
{
}

DecryptVerifyFilesWizard::~DecryptVerifyFilesWizard()
{
}

void DecryptVerifyFilesWizard::setOutputDirectory(const QString &dir)
{
    d->operationsPage.setOutputDirectory(dir);
}

QString DecryptVerifyFilesWizard::outputDirectory() const
{
    return d->operationsPage.outputDirectory();
}

bool DecryptVerifyFilesWizard::useOutputDirectory() const
{
    return d->operationsPage.useOutputDirectory();
}

DecryptVerifyOperationWidget *DecryptVerifyFilesWizard::operationWidget(unsigned int idx)
{
    d->ensureIndexAvailable(idx);
    return d->operationsPage.widget(idx);
}

void DecryptVerifyFilesWizard::onNext(int id)
{
    if (id == OperationsPage) {
        QTimer::singleShot(0, this, &DecryptVerifyFilesWizard::operationPrepared);
    }
    Wizard::onNext(id);
}

void DecryptVerifyFilesWizard::setTaskCollection(const std::shared_ptr<TaskCollection> &coll)
{
    kleo_assert(coll);
    d->resultPage.setTaskCollection(coll);
}

DecryptVerifyFilesWizard::Private::Private(DecryptVerifyFilesWizard *qq)
    : q(qq)
    , operationsPage(q)
    , resultPage(q)
{
    q->setPage(DecryptVerifyFilesWizard::OperationsPage, &operationsPage);
    q->setPage(DecryptVerifyFilesWizard::ResultPage, &resultPage);

    std::vector<int> order;
    order.push_back(DecryptVerifyFilesWizard::OperationsPage);
    order.push_back(DecryptVerifyFilesWizard::ResultPage);
    q->setPageOrder(order);
    operationsPage.setCommitPage(true);
}

DecryptVerifyFilesWizard::Private::~Private()
{
}

OperationsWidget::OperationsWidget(QWidget *p)
    : WizardPage(p)
    , m_widgets()
    , m_ui(this)
{
    setTitle(i18n("<b>Choose operations to be performed</b>"));
    setSubTitle(
        i18n("Here you can check and, if needed, override "
             "the operations Kleopatra detected for the input given."));
    setCommitPage(true);
    setCustomNextButton(KGuiItem(i18nc("@action:button", "&Decrypt/Verify")));
}

OperationsWidget::~OperationsWidget()
{
}

OperationsWidget::UI::UI(OperationsWidget *q)
    : useOutputDirectoryCB(i18n("Create all output files in a single folder"), q)
    , outputDirectoryLB(i18n("&Output folder:"), q)
    , outputDirectoryFNR(q)
    , scrollArea(q)
    , vlay(q)
    , hlay()
{
    Q_SET_OBJECT_NAME(useOutputDirectoryCB);
    Q_SET_OBJECT_NAME(outputDirectoryLB);
    Q_SET_OBJECT_NAME(outputDirectoryFNR);
    Q_SET_OBJECT_NAME(scrollArea);

    Q_SET_OBJECT_NAME(vlay);
    Q_SET_OBJECT_NAME(hlay);

    outputDirectoryFNR.setFilter(QDir::Dirs);

    useOutputDirectoryCB.setChecked(true);
    connect(&useOutputDirectoryCB, &QCheckBox::toggled, &outputDirectoryLB, &QLabel::setEnabled);
    connect(&useOutputDirectoryCB, &QCheckBox::toggled, &outputDirectoryFNR, &FileNameRequester::setEnabled);

    auto widget = new QWidget;
    scrollArea.setWidget(widget);
    new QVBoxLayout(widget);

    Q_ASSERT(qobject_cast<QBoxLayout *>(scrollArea.widget()->layout()));
    static_cast<QBoxLayout *>(scrollArea.widget()->layout())->addStretch(1);
    outputDirectoryLB.setBuddy(&outputDirectoryFNR);

    hlay.setContentsMargins(0, 0, 0, 0);

    vlay.addWidget(&scrollArea, 1);
    vlay.addWidget(&useOutputDirectoryCB);
    vlay.addLayout(&hlay);
    hlay.addWidget(&outputDirectoryLB);
    hlay.addWidget(&outputDirectoryFNR);
}

void OperationsWidget::ensureIndexAvailable(unsigned int idx)
{
    if (idx < m_widgets.size()) {
        return;
    }

    Q_ASSERT(m_ui.scrollArea.widget());
    Q_ASSERT(qobject_cast<QBoxLayout *>(m_ui.scrollArea.widget()->layout()));
    QBoxLayout &blay = *static_cast<QBoxLayout *>(m_ui.scrollArea.widget()->layout());

    for (unsigned int i = m_widgets.size(); i < idx + 1; ++i) {
        if (i) {
            blay.insertWidget(blay.count() - 1, new HLine(m_ui.scrollArea.widget()));
        }
        auto w = new DecryptVerifyOperationWidget(m_ui.scrollArea.widget());
        blay.insertWidget(blay.count() - 1, w);
        w->show();
        connect(w, &DecryptVerifyOperationWidget::changed, this, &WizardPage::completeChanged);
        m_widgets.push_back(w);
    }
}

#include "decryptverifyfileswizard.moc"

#include "moc_decryptverifyfileswizard.cpp"
