/*
    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2020 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#pragma once

#include <QWidget>

#include <memory>

namespace Kleo
{
namespace Dialogs
{

class CertificateDetailsInputWidget : public QWidget
{
    Q_OBJECT
public:
    explicit CertificateDetailsInputWidget(QWidget *parent = nullptr);
    ~CertificateDetailsInputWidget() override;

    void setName(const QString &name);

    void setEmail(const QString &email);
    QString email() const;

    QString dn() const;

Q_SIGNALS:
    void validityChanged(bool valid);

private:
    class Private;
    const std::unique_ptr<Private> d;
};

}
}
