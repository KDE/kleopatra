/*
    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2008 Klarälvdalens Datakonsult AB

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#pragma once

#include <QDialog>

#include <memory>
#include <vector>

namespace Kleo
{

class SelfTest;

namespace Dialogs
{

class SelfTestDialog : public QDialog
{
    Q_OBJECT
    Q_PROPERTY(bool runAtStartUp READ runAtStartUp WRITE setRunAtStartUp)
public:
    explicit SelfTestDialog(QWidget *parent = nullptr, Qt::WindowFlags f = {});
    ~SelfTestDialog() override;

    void setAutomaticMode(bool automatic);

    void setTests(const std::vector<std::shared_ptr<SelfTest>> &tests);

    void setRunAtStartUp(bool run);
    bool runAtStartUp() const;

Q_SIGNALS:
    void updateRequested();

private:
    class Private;
    const std::unique_ptr<Private> d;
};

}
}
