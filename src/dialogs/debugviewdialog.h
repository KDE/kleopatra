// SPDX-FileCopyrightText: 2024 g10 Code GmbH
// SPDX-FileContributor: Tobias Fella <tobias.fella@gnupg.com>
// SPDX-License-Identifier: GPL-2.0-or-later

#pragma once

#include <QDialog>

namespace Kleo
{
namespace Dialogs
{

class DebugViewDialog : public QDialog
{
    Q_OBJECT

public:
    explicit DebugViewDialog(QWidget *parent);

private:
    class Private;
    std::unique_ptr<Private> d;
};

}
}
