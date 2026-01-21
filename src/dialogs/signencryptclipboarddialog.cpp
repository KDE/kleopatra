// SPDX-FileCopyrightText: 2024 g10 Code GmbH
// SPDX-FileContributor: Tobias Fella <tobias.fella@gnupg.com>
// SPDX-License-Identifier: GPL-2.0-or-later

#include "signencryptclipboarddialog.h"

#include "crypto/gui/resultpage.h"
#include "crypto/gui/signencryptwidget.h"
#include "crypto/signencrypttask.h"
#include "crypto/taskcollection.h"
#include "settings.h"
#include "utils/input.h"
#include "utils/output.h"

#include <Libkleo/Compliance>

#include <gpgme++/key.h>

#include <KAdjustingScrollArea>
#include <KLocalizedString>
#include <KMessageBox>
#include <KTitleWidget>

#include <QApplication>
#include <QClipboard>
#include <QDialogButtonBox>
#include <QMimeData>
#include <QPushButton>
#include <QStackedLayout>
#include <QVBoxLayout>

using namespace Kleo;
using namespace Kleo::Crypto;
using namespace Kleo::Commands;

using namespace Qt::Literals::StringLiterals;

class SignEncryptPage : public QWidget
{
public:
    explicit SignEncryptPage(Kleo::Commands::SignEncryptClipboardCommand::Mode mode, QWidget *parent = nullptr)
        : QWidget(parent)
    {
        auto mainLayout = new QVBoxLayout(this);
        mainLayout->setContentsMargins({});
        auto scrollArea = new KAdjustingScrollArea;
        mainLayout->addWidget(scrollArea);

        auto wrapper = new QWidget;
        scrollArea->setWidget(wrapper);

        scrollArea->setFrameStyle(0);
        auto vLay = new QVBoxLayout(wrapper);
        vLay->setContentsMargins({});
        m_widget = new SignEncryptWidget(this, true);
        m_widget->setSigningChecked(mode == SignEncryptClipboardCommand::Mode::Sign || mode == SignEncryptClipboardCommand::Mode::SignEncrypt);
        m_widget->setEncryptionChecked(mode == SignEncryptClipboardCommand::Mode::Encrypt || mode == SignEncryptClipboardCommand::Mode::SignEncrypt);
        vLay->addWidget(m_widget);
    }

    std::vector<GpgME::Key> recipients() const
    {
        return m_widget->recipients();
    }

    GpgME::Key signer() const
    {
        const auto key = m_widget->signUserId().parent();
        if (!key.isNull()) {
            return key;
        }
        return {};
    }

    SignEncryptWidget *signEncryptWidget() const
    {
        return m_widget;
    }

    bool isDeVsAndValid() const
    {
        return m_widget->isDeVsAndValid();
    }

    bool validatePage()
    {
        if (DeVSCompliance::isActive() && !DeVSCompliance::isCompliant()) {
            return false;
        }

        return m_widget->isComplete();
    }

private:
    SignEncryptWidget *m_widget;
};

SignEncryptClipboardDialog::SignEncryptClipboardDialog(Kleo::Commands::SignEncryptClipboardCommand::Mode mode)
    : QDialog(nullptr)
{
    setWindowTitle(i18nc("@title:dialog", "Sign/Encrypt Clipboard"));
    auto layout = new QVBoxLayout(this);

    auto title = new KTitleWidget;
    title->setText(i18nc("@title", "Sign/Encrypt Clipboard"));
    layout->addWidget(title);

    mStackedLayout = new QStackedLayout;

    mSignEncryptPage = new SignEncryptPage(mode, this);

    mStackedLayout->addWidget(mSignEncryptPage);

    auto resultPage = new Kleo::Crypto::Gui::ResultPage;
    mStackedLayout->addWidget(resultPage);

    resultPage->setKeepOpenWhenDone(mode == SignEncryptClipboardCommand::Mode::Sign ? Settings{}.showResultsAfterSigningClipboard()
                                                                                    : Settings{}.showResultsAfterEncryptingClipboard());
    connect(resultPage, &Gui::ResultPage::completeChanged, this, [this, resultPage]() {
        if (resultPage->autoAdvance()) {
            close();
        }
    });

    connect(this, &QDialog::finished, this, [resultPage, mode]() {
        Settings settings;
        if (mode == SignEncryptClipboardCommand::Mode::Sign) {
            settings.setShowResultsAfterSigningClipboard(resultPage->keepOpenWhenDone());
        } else {
            settings.setShowResultsAfterEncryptingClipboard(resultPage->keepOpenWhenDone());
        }
        settings.save();
    });

    layout->addLayout(mStackedLayout);

    auto buttons = new QDialogButtonBox;

    if (DeVSCompliance::isActive()) {
        /* We use a custom button to display a label next to the
           buttons. */
        mComplianceLabelButton = buttons->addButton(QString(), QDialogButtonBox::ActionRole);
        /* We style the button so that it looks and acts like a
           label.  */
        mComplianceLabelButton->setStyleSheet(QStringLiteral("border: none"));
        mComplianceLabelButton->setFocusPolicy(Qt::NoFocus);
    }

    mOkButton = buttons->addButton(i18nc("@action:button", "Continue"), QDialogButtonBox::ActionRole);
    auto cancelButton = buttons->addButton(QDialogButtonBox::Cancel);
    connect(cancelButton, &QPushButton::clicked, this, [this]() {
        reject();
    });

    layout->addWidget(buttons);

    connect(mSignEncryptPage->signEncryptWidget(), &SignEncryptWidget::operationChanged, this, &SignEncryptClipboardDialog::updateButtons);
    connect(&mAppPaletteWatcher, &ApplicationPaletteWatcher::paletteChanged, this, &SignEncryptClipboardDialog::updateButtons);

    connect(mOkButton, &QPushButton::clicked, this, [this, resultPage, title]() {
        if (mStackedLayout->currentIndex() == 0) {
            if (!mSignEncryptPage->signEncryptWidget()->validate()) {
                return;
            }
            m_task = std::make_shared<SignEncryptTask>();
            m_task->setDataSource(Task::Clipboard);
            auto output = Output::createFromClipboard();
            m_task->setInput(m_input);
            m_task->setOutput(output);
            title->setText(i18nc("@title", "Results"));

            auto recipients = mSignEncryptPage->recipients();
            auto signer = mSignEncryptPage->signer();

            m_task->setRecipients(recipients);
            m_task->setEncrypt(!recipients.empty());
            m_task->setSigners({signer});
            m_task->setSign(!signer.isNull());
            m_task->setClearsign(!signer.isNull() && recipients.empty() && signer.protocol() == GpgME::OpenPGP);
            m_task->setEncryptSymmetric(mSignEncryptPage->signEncryptWidget()->encryptSymmetric());
            m_task->setAsciiArmor(true);

            mStackedLayout->setCurrentIndex(1);
            mOkButton->setText(i18nc("@action:button", "Finish"));
            std::shared_ptr<TaskCollection> coll(new TaskCollection);
            coll->setTasks({m_task});
            resultPage->setTaskCollection(coll);
            m_task->start();
        } else {
            accept();
        }
    });

    auto onClipboardAvailable = [this]() {
        const auto mimeData = qApp->clipboard()->mimeData();
        if (!mimeData->hasFormat("text/plain"_L1)) {
            KMessageBox::information(this, i18nc("@info", "The clipboard does not contain text."));
            QMetaObject::invokeMethod(this, &QDialog::reject, Qt::QueuedConnection);
        } else {
            m_input = Input::createFromClipboard();
        }
    };

    if (qApp->platformName() != "wayland"_L1) {
        onClipboardAvailable();
    } else {
        connect(
            qApp->clipboard(),
            &QClipboard::dataChanged,
            this,
            [onClipboardAvailable]() {
                onClipboardAvailable();
            },
            Qt::SingleShotConnection);
    }

    updateButtons();
}

void SignEncryptClipboardDialog::updateButtons()
{
    if (mStackedLayout->currentIndex() == 1) {
        return;
    }
    QString label;
    switch (mSignEncryptPage->signEncryptWidget()->currentOp()) {
    case SignEncryptWidget::Sign:
        label = i18nc("@action:button", "Sign");
        break;
    case SignEncryptWidget::Encrypt:
        label = i18nc("@action:button", "Encrypt");
        break;
    case SignEncryptWidget::SignAndEncrypt:
        label = i18nc("@action:button", "Sign / Encrypt");
        break;
    default:;
    };
    if (!label.isEmpty()) {
        mOkButton->setText(label);
        if (DeVSCompliance::isActive()) {
            const bool de_vs = DeVSCompliance::isCompliant() && mSignEncryptPage->isDeVsAndValid();
            DeVSCompliance::decorate(mOkButton, de_vs);

            mOkButton->setToolTip(DeVSCompliance::name(de_vs));
            mComplianceLabelButton->setText(DeVSCompliance::name(de_vs));
            // set the style-sheet again to update the colors on palette changes
            mComplianceLabelButton->setStyleSheet(QStringLiteral("border: none"));
        }
    } else {
        mOkButton->setText(i18nc("@action:button", "Next"));
        mOkButton->setIcon(QIcon());
        mOkButton->setStyleSheet(QString());
    }
    mOkButton->setEnabled(mSignEncryptPage->validatePage());
}

SignEncryptClipboardDialog::~SignEncryptClipboardDialog()
{
    if (m_task) {
        m_task->cancel();
    }
}

#include "moc_signencryptclipboarddialog.cpp"
