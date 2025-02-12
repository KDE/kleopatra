/*
    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2008 Klarälvdalens Datakonsult AB
    SPDX-FileCopyrightText: 2022 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#pragma once

#include <QDialog>

#include <memory>

namespace Kleo
{

class AddUserIDDialog : public QDialog
{
    Q_OBJECT
public:
    explicit AddUserIDDialog(QWidget *parent = nullptr, Qt::WindowFlags f = {});
    ~AddUserIDDialog() override;

    void setName(const QString &name);
    QString name() const;

    void setEmail(const QString &email);
    QString email() const;

    /**
     * Returns the user ID built from the entered name and/or email address.
     */
    QString userID() const;

private:
    class Private;
    const std::unique_ptr<Private> d;
};

} // namespace Kleo
