/* -*- mode: c++; c-basic-offset:4 -*-
    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2020 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#pragma once

#include <QDialog>

#include <memory>

namespace Kleo
{
namespace Dialogs
{

class CreateCSRForCardKeyDialog : public QDialog
{
    Q_OBJECT
public:
    explicit CreateCSRForCardKeyDialog(QWidget *parent = nullptr);
    ~CreateCSRForCardKeyDialog() override;

    void setName(const QString &name);

    void setEmail(const QString &email);
    QString email() const;

    QString dn() const;

private:
    class Private;
    const std::unique_ptr<Private> d;
};

}
}
