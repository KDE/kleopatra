/*
    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2008 Klarälvdalens Datakonsult AB

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#pragma once

#include <QHeaderView>

#include <memory>
#include <vector>

namespace Kleo
{

class HeaderView : public QHeaderView
{
    Q_OBJECT
public:
    explicit HeaderView(Qt::Orientation o, QWidget *parent = nullptr);
    ~HeaderView() override;

    void setSectionSizes(const std::vector<int> &sizes);
    std::vector<int> sectionSizes() const;

private:
    //@{
    /*! Defined, but not implemented, to catch at least some usage errors */
    void setResizeMode(int, ResizeMode);
    //@}
private:
    class Private;
    const std::unique_ptr<Private> d;
};

}
