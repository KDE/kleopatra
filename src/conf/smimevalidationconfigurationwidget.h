/*
    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2008 Klarälvdalens Datakonsult AB

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#pragma once

#include <QWidget>

#include <memory>

namespace Kleo
{
namespace Config
{

class SMimeValidationConfigurationWidget : public QWidget
{
    Q_OBJECT
public:
    explicit SMimeValidationConfigurationWidget(QWidget *parent = nullptr, Qt::WindowFlags f = {});
    ~SMimeValidationConfigurationWidget() override;

    void load();
    void save() const;
    void defaults();

Q_SIGNALS:
    void changed();

private:
    class Private;
    const std::unique_ptr<Private> d;
};

}
}
