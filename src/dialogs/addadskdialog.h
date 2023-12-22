/*
    SPDX-FileCopyrightText: 2024 g10 Code GmbH
    SPDX-FileContributor: Tobias Fella <tobias.fella@gnupg.com>

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#pragma once

#include <Libkleo/KeyUsage>

#include <QDialog>

#include <gpgme++/key.h>

#include <memory.h>

namespace Kleo
{
namespace Dialogs
{

class AddADSKDialog : public QDialog
{
    Q_OBJECT
public:
    explicit AddADSKDialog(const GpgME::Key &parent, QWidget *p = nullptr);
    ~AddADSKDialog() override;

    GpgME::Key adsk() const;

private:
    class Private;
    std::unique_ptr<Private> d;
};

}
}
