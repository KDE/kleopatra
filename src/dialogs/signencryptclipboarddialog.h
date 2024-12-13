// SPDX-FileCopyrightText: 2024 g10 Code GmbH
// SPDX-FileContributor: Tobias Fella <tobias.fella@gnupg.com>
// SPDX-License-Identifier: GPL-2.0-or-later

#pragma once

#include <QDialog>

namespace Kleo
{
class Input;
namespace Crypto
{
class SignEncryptTask;
}
}

class SignEncryptClipboardDialog : public QDialog
{
    Q_OBJECT

public:
    explicit SignEncryptClipboardDialog(QWidget *parent = nullptr);
    ~SignEncryptClipboardDialog();

    void setPlainText(const QString &plainText);

private:
    QString m_plainText;
    std::shared_ptr<Kleo::Crypto::SignEncryptTask> m_task;
    std::shared_ptr<Kleo::Input> m_input;
};
