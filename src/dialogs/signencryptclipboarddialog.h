// SPDX-FileCopyrightText: 2024 g10 Code GmbH
// SPDX-FileContributor: Tobias Fella <tobias.fella@gnupg.com>
// SPDX-License-Identifier: GPL-2.0-or-later

#pragma once

#include "commands/signencryptclipboardcommand.h"

#include <Libkleo/ApplicationPaletteWatcher>

#include <QDialog>

namespace Kleo
{
class Input;
namespace Crypto
{
class SignEncryptTask;
}
}

class SignEncryptPage;

class SignEncryptClipboardDialog : public QDialog
{
    Q_OBJECT

public:
    explicit SignEncryptClipboardDialog(Kleo::Commands::SignEncryptClipboardCommand::Mode mode);
    ~SignEncryptClipboardDialog() override;

private:
    void updateButtons();

    ApplicationPaletteWatcher mAppPaletteWatcher;
    SignEncryptPage *mSignEncryptPage = nullptr;
    QPushButton *mOkButton = nullptr;
    QPushButton *mComplianceLabelButton = nullptr;
    std::shared_ptr<Kleo::Crypto::SignEncryptTask> m_task;
    std::shared_ptr<Kleo::Input> m_input;
};
