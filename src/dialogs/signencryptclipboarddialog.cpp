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

#include <gpgme++/key.h>

#include <KLocalizedString>

#include <QDialogButtonBox>
#include <QPushButton>
#include <QStackedLayout>
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
    auto mOkButton = buttons->addButton(i18nc("@action:button", "Continue"), QDialogButtonBox::ActionRole);
    buttons->addButton(QDialogButtonBox::Cancel);
    layout->addWidget(buttons);

    connect(mOkButton, &QPushButton::clicked, this, [signEncryptPage, stackedLayout, resultPage]() {
        std::shared_ptr<SignEncryptTask> task(new SignEncryptTask());
        task->setDataSource(Task::Clipboard);
        auto input = Input::createFromClipboard();
        auto output = Output::createFromClipboard();
        task->setInput(input);
        task->setOutput(output);

        auto recipients = signEncryptPage->recipients();
        auto signer = signEncryptPage->signer();

        task->setRecipients(recipients);
        task->setEncrypt(recipients.size() > 0);
        task->setSigners({signer});
        task->setSign(!signer.isNull());
        task->setClearsign(false); // TODO
        task->setDetachedSignature(true); // TODO
        task->setEncryptSymmetric(false); // TODO
        task->start();

        stackedLayout->setCurrentIndex(1);

        std::shared_ptr<TaskCollection> coll(new TaskCollection);
        coll->setTasks({task});
        resultPage->setTaskCollection(coll);
    });
}
