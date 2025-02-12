/*
    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2010 Klarälvdalens Datakonsult AB

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#pragma once

#include <QDialog>
#include <QMetaType>

#ifndef QT_NO_DIRMODEL

#include <memory>

namespace Kleo
{
namespace Crypto
{
namespace Gui
{

class VerifyChecksumsDialog : public QDialog
{
    Q_OBJECT
    Q_ENUMS(Status)
public:
    explicit VerifyChecksumsDialog(QWidget *parent = nullptr);
    ~VerifyChecksumsDialog() override;

    enum Status {
        Unknown,
        OK,
        Failed,
        Error,
        NumStatii,
    };

public Q_SLOTS:
    void setBaseDirectories(const QStringList &bases);
    void setProgress(int current, int total);
    void setStatus(const QString &file, Kleo::Crypto::Gui::VerifyChecksumsDialog::Status status);
    void setErrors(const QStringList &errors);
    void clearStatusInformation();

Q_SIGNALS:
    void canceled();

private:
    Q_PRIVATE_SLOT(d, void slotErrorButtonClicked())
    class Private;
    const std::unique_ptr<Private> d;
};
}
}
}

Q_DECLARE_METATYPE(Kleo::Crypto::Gui::VerifyChecksumsDialog::Status)

#endif // QT_NO_DIRMODEL
