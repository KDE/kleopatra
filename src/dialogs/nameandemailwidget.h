/* -*- mode: c++; c-basic-offset:4 -*-
    dialogs/nameandemailwidget.h

    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2008 Klarälvdalens Datakonsult AB
    SPDX-FileCopyrightText: 2022 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#pragma once

#include <QWidget>

#include <memory>

namespace Kleo
{

class NameAndEmailWidget : public QWidget
{
    Q_OBJECT
public:
    explicit NameAndEmailWidget(QWidget *parent = nullptr, Qt::WindowFlags f = {});
    ~NameAndEmailWidget() override;

    void setName(const QString &name);
    QString name() const;
    void setNameIsRequired(bool required);
    bool nameIsRequired() const;
    void setNameLabel(const QString &label);
    QString nameLabel() const;
    void setNameHint(const QString &hint);
    QString nameHint() const;
    void setNamePattern(const QString &pattern);
    QString nameError() const;

    void setEmail(const QString &email);
    QString email() const;
    void setEmailIsRequired(bool required);
    bool emailIsRequired() const;
    void setEmailLabel(const QString &label);
    QString emailLabel() const;
    void setEmailHint(const QString &hint);
    QString emailHint() const;
    void setEmailPattern(const QString &pattern);
    QString emailError() const;

    /**
     * Returns \c true if both inputs have a valid value.
     */
    bool isValid() const;

    /**
     * Returns the user ID built from the entered name and/or email address.
     */
    QString userID() const;

Q_SIGNALS:
    void userIDChanged() const;

private:
    class Private;
    const std::unique_ptr<Private> d;
};

} // namespace Kleo
