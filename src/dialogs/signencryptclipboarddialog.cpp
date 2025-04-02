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

    auto stackedLayout = new QStackedLayout;

    auto signEncryptPage = new SignEncryptPage(mode, this);

    stackedLayout->addWidget(signEncryptPage);

    auto resultPage = new Kleo::Crypto::Gui::ResultPage;
    stackedLayout->addWidget(resultPage);

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

    layout->addLayout(stackedLayout);

    auto buttons = new QDialogButtonBox;

    QPushButton *labelButton = nullptr;

    if (DeVSCompliance::isActive()) {
        /* We use a custom button to display a label next to the
           buttons. */
        labelButton = buttons->addButton(QString(), QDialogButtonBox::ActionRole);
        /* We style the button so that it looks and acts like a
           label.  */
        labelButton->setStyleSheet(QStringLiteral("border: none"));
        labelButton->setFocusPolicy(Qt::NoFocus);
    }

    auto okButton = buttons->addButton(i18nc("@action:button", "Continue"), QDialogButtonBox::ActionRole);
    auto cancelButton = buttons->addButton(QDialogButtonBox::Cancel);
    connect(cancelButton, &QPushButton::clicked, this, [this]() {
        reject();
    });

    layout->addWidget(buttons);

    connect(signEncryptPage->signEncryptWidget(), &SignEncryptWidget::operationChanged, this, [okButton, signEncryptPage, labelButton](const auto op) {
        QString label;
        switch (op) {
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
            okButton->setText(label);
            if (DeVSCompliance::isActive()) {
                const bool de_vs = DeVSCompliance::isCompliant() && signEncryptPage->isDeVsAndValid();
                DeVSCompliance::decorate(okButton, de_vs);

                okButton->setToolTip(DeVSCompliance::name(de_vs));
                labelButton->setText(DeVSCompliance::name(de_vs));
            }
        } else {
            okButton->setText(i18nc("@action:button", "Next"));
            okButton->setIcon(QIcon());
            okButton->setStyleSheet(QString());
        }
        okButton->setEnabled(signEncryptPage->validatePage());
    });

    connect(okButton, &QPushButton::clicked, this, [this, signEncryptPage, stackedLayout, resultPage, okButton, title]() {
        if (stackedLayout->currentIndex() == 0) {
            m_task = std::make_shared<SignEncryptTask>();
            m_task->setDataSource(Task::Clipboard);
            auto output = Output::createFromClipboard();
            m_task->setInput(m_input);
            m_task->setOutput(output);
            title->setText(i18nc("@title", "Results"));

            auto recipients = signEncryptPage->recipients();
            auto signer = signEncryptPage->signer();

            m_task->setRecipients(recipients);
            m_task->setEncrypt(!recipients.empty());
            m_task->setSigners({signer});
            m_task->setSign(!signer.isNull());
            m_task->setClearsign(!signer.isNull() && recipients.empty() && signer.protocol() == GpgME::OpenPGP);
            m_task->setEncryptSymmetric(signEncryptPage->signEncryptWidget()->encryptSymmetric());
            m_task->setAsciiArmor(true);

            stackedLayout->setCurrentIndex(1);
            okButton->setText(i18nc("@action:button", "Finish"));

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
}

SignEncryptClipboardDialog::~SignEncryptClipboardDialog()
{
    if (m_task) {
        m_task->cancel();
    }
}

#include "moc_signencryptclipboarddialog.cpp"
