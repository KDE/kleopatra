/* -*- mode: c++; c-basic-offset:4 -*-
    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2007 Klarälvdalens Datakonsult AB

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#pragma once

#include <memory>
#include <vector>

#include <QDialog>

namespace Kleo
{
namespace Crypto
{
namespace Gui
{

class WizardPage;

class Wizard : public QDialog
{
    Q_OBJECT
public:
    explicit Wizard(QWidget *parent = nullptr, Qt::WindowFlags f = {});
    ~Wizard() override;

    enum Page {
        InvalidPage = -1,
    };

    void setPage(int id, WizardPage *page);

    const WizardPage *page(int id) const;
    WizardPage *page(int id);

    void setPageOrder(const std::vector<int> &pages);
    void setPageVisible(int id, bool visible);

    void setCurrentPage(int id);

    int currentPage() const;

    const WizardPage *currentPageWidget() const;
    WizardPage *currentPageWidget();

    bool canGoToPreviousPage() const;
    bool canGoToNextPage() const;

public Q_SLOTS:
    void next();
    void back();

Q_SIGNALS:
    void canceled();

protected:
    virtual void onNext(int currentId);
    virtual void onBack(int currentId);

private:
    class Private;
    const std::unique_ptr<Private> d;
    Q_PRIVATE_SLOT(d, void updateButtonStates())
    Q_PRIVATE_SLOT(d, void updateHeader())
};

}
}
}
