// SPDX-FileCopyrightText: 2024 g10 Code GmbH
// SPDX-FileContributor: Tobias Fella <tobias.fella@gnupg.com>
// SPDX-License-Identifier: GPL-2.0-or-later

#include "signencryptclipboarddialog.h"

#include "crypto/gui/resultpage.h"
#include "crypto/gui/signencryptwidget.h"
#include "crypto/signencrypttask.h"
#include "crypto/task.h"
#include "crypto/taskcollection.h"
#include "utils/input.h"
#include "utils/output.h"
#include "utils/scrollarea.h"

#include <Libkleo/Compliance>

#include <gpgme++/key.h>

#include <KLocalizedString>
#include <KMessageBox>

#include <QApplication>
#include <QClipboard>
#include <QDialogButtonBox>
#include <QPushButton>
#include <QStackedLayout>
#include <QTimer>
#include <QVBoxLayout>

using namespace Kleo;
using namespace Kleo::Crypto;

class SignEncryptPage : public QWidget
{
public:
    explicit SignEncryptPage(QWidget *parent = nullptr)
        : QWidget(parent)
    {
        auto mainLayout = new QVBoxLayout(this);
        mainLayout->setContentsMargins({});
        auto scrollArea = new Kleo::ScrollArea;
        mainLayout->addWidget(scrollArea);

        auto wrapper = new QWidget;
        scrollArea->setWidget(wrapper);

        scrollArea->setFrameStyle(0);
        auto vLay = new QVBoxLayout(wrapper);
        vLay->setContentsMargins({});
        m_widget = new SignEncryptWidget(this, true);
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

private:
    SignEncryptWidget *m_widget;
};

SignEncryptClipboardDialog::SignEncryptClipboardDialog(QWidget *parent)
    : QDialog(parent)
{
    setWindowTitle(i18nc("@title:dialog", "Sign/Encrypt Clipboard"));
    auto layout = new QVBoxLayout(this);
    auto stackedLayout = new QStackedLayout;

    auto signEncryptPage = new SignEncryptPage;
    stackedLayout->addWidget(signEncryptPage);

    auto resultPage = new Kleo::Crypto::Gui::ResultPage;
    stackedLayout->addWidget(resultPage);

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
    buttons->addButton(QDialogButtonBox::Cancel);

    layout->addWidget(buttons);

    connect(signEncryptPage->signEncryptWidget(), &SignEncryptWidget::operationChanged, this, [okButton, signEncryptPage, labelButton]() {
        okButton->setText(signEncryptPage->signEncryptWidget()->continueButtonText());
        if (signEncryptPage->signEncryptWidget()->isComplete() && DeVSCompliance::isActive()) {
            const bool de_vs = DeVSCompliance::isCompliant() && signEncryptPage->signEncryptWidget()->isDeVsAndValid();
            DeVSCompliance::decorate(okButton, de_vs);

            okButton->setToolTip(DeVSCompliance::name(de_vs));
            labelButton->setText(DeVSCompliance::name(de_vs));
        } else {
            if (labelButton) {
                labelButton->setText({});
            }
            okButton->setIcon(QIcon());
            okButton->setStyleSheet(QString());
        }
        okButton->setEnabled(signEncryptPage->signEncryptWidget()->isComplete());
    });

    connect(okButton, &QPushButton::clicked, this, [this, signEncryptPage, stackedLayout, resultPage, okButton]() {
        if (stackedLayout->currentIndex() == 0) {
            m_task = std::make_shared<SignEncryptTask>();
            m_task->setDataSource(Task::Clipboard);
            auto output = Output::createFromClipboard();
            m_task->setInput(m_input);
            m_task->setOutput(output);

            auto recipients = signEncryptPage->recipients();
            auto signer = signEncryptPage->signer();

            m_task->setRecipients(recipients);
            m_task->setEncrypt(recipients.size() > 0);
            m_task->setSigners({signer});
            m_task->setSign(!signer.isNull());
            m_task->setClearsign(!signer.isNull() && recipients.size() == 0 && signer.protocol() == GpgME::OpenPGP);
            m_task->setEncryptSymmetric(signEncryptPage->signEncryptWidget()->encryptSymmetric());
            m_task->setAsciiArmor(true);
            m_task->start();

            stackedLayout->setCurrentIndex(1);
            okButton->setText(i18nc("@action:button", "Finish"));

            std::shared_ptr<TaskCollection> coll(new TaskCollection);
            coll->setTasks({m_task});
            resultPage->setTaskCollection(coll);
        } else {
            accept();
        }
    });

    QTimer::singleShot(100, this, [this]() {
        if (qApp->clipboard()->text().isEmpty()) {
            KMessageBox::information(this,
                                     i18nc("@info", "The clipboard does not contain data that can be encrypted"),
                                     i18nc("@title:dialog", "Sign/Encrypt Clipboard"));
            reject();
        } else {
            m_input = Input::createFromClipboard();
        }
    });
}

SignEncryptClipboardDialog::~SignEncryptClipboardDialog()
{
    if (m_task) {
        m_task->cancel();
    }
}
