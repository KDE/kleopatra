/*
    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2007 Klarälvdalens Datakonsult AB

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#pragma once

#include <crypto/gui/wizard.h>

#include <memory>

namespace Kleo
{
namespace Crypto
{
class Task;
class TaskCollection;
namespace Gui
{

class DecryptVerifyOperationWidget;

class DecryptVerifyFilesWizard : public Wizard
{
    Q_OBJECT
public:
    enum Page {
        OperationsPage = 0,
        ResultPage,
    };

    explicit DecryptVerifyFilesWizard(QWidget *parent = nullptr, Qt::WindowFlags f = {});
    ~DecryptVerifyFilesWizard() override;

    void setOutputDirectory(const QString &dir);
    QString outputDirectory() const;
    bool useOutputDirectory() const;

    void setTaskCollection(const std::shared_ptr<TaskCollection> &coll);

    DecryptVerifyOperationWidget *operationWidget(unsigned int idx);

Q_SIGNALS:
    void operationPrepared();

private:
    void onNext(int id) override;

private:
    class Private;
    const std::unique_ptr<Private> d;
};

}
}
}
