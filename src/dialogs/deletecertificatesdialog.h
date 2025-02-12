/*
    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2009 Klarälvdalens Datakonsult AB

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#pragma once

#include <QDialog>

#include <memory>
#include <vector>

namespace GpgME
{
class Key;
}

namespace Kleo
{
namespace Dialogs
{

class DeleteCertificatesDialog : public QDialog
{
    Q_OBJECT
public:
    explicit DeleteCertificatesDialog(QWidget *parent = nullptr);
    ~DeleteCertificatesDialog() override;

    void setSelectedKeys(const std::vector<GpgME::Key> &keys);
    void setUnselectedKeys(const std::vector<GpgME::Key> &keys);

    std::vector<GpgME::Key> keys() const;

    void accept() override;

private:
    class Private;
    const std::unique_ptr<Private> d;
};

}
}
