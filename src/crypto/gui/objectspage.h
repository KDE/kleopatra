/*
    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2007 Klarälvdalens Datakonsult AB

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#pragma once

#include <crypto/gui/wizardpage.h>

#include <QStringList>

#include <memory>

namespace Kleo
{
namespace Crypto
{
namespace Gui
{

class ObjectsPage : public WizardPage
{
    Q_OBJECT
public:
    explicit ObjectsPage(QWidget *parent = nullptr, Qt::WindowFlags f = {});
    ~ObjectsPage() override;

    bool isComplete() const override;
    void setFiles(const QStringList &files);
    QStringList files() const;

private:
    class Private;
    const std::unique_ptr<Private> d;
    Q_PRIVATE_SLOT(d, void add())
    Q_PRIVATE_SLOT(d, void remove())
    Q_PRIVATE_SLOT(d, void listSelectionChanged())
};

}
}
}
