/*
    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2008, 2009 Klarälvdalens Datakonsult AB

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#pragma once

#include <QWizardPage>

#include <memory>

namespace Kleo
{
namespace Crypto
{
class TaskCollection;
class Task;
}
}

namespace Kleo
{
namespace Crypto
{
namespace Gui
{

class NewResultPage : public QWizardPage
{
    Q_OBJECT
public:
    explicit NewResultPage(QWidget *parent = nullptr);
    ~NewResultPage() override;

    void setTaskCollection(const std::shared_ptr<TaskCollection> &coll);
    void addTaskCollection(const std::shared_ptr<TaskCollection> &coll);

    bool isComplete() const override;

Q_SIGNALS:
    void linkActivated(const QString &link);

private:
    class Private;
    const std::unique_ptr<Private> d;
    Q_PRIVATE_SLOT(d, void result(std::shared_ptr<const Kleo::Crypto::Task::Result>))
    Q_PRIVATE_SLOT(d, void started(std::shared_ptr<Kleo::Crypto::Task>))
    Q_PRIVATE_SLOT(d, void allDone())
};

}
}
}
