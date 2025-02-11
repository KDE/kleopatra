/* -*- mode: c++; c-basic-offset:4 -*-
    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2007 Klarälvdalens Datakonsult AB

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#pragma once

#include <QWidget>

#include <memory>
#include <vector>

namespace Kleo
{
class ArchiveDefinition;
}

namespace Kleo
{
namespace Crypto
{
namespace Gui
{

class DecryptVerifyOperationWidget : public QWidget
{
    Q_OBJECT
    Q_ENUMS(Mode)
    Q_PROPERTY(Mode mode READ mode WRITE setMode)
    Q_PROPERTY(QString inputFileName READ inputFileName WRITE setInputFileName)
    Q_PROPERTY(QString signedDataFileName READ signedDataFileName WRITE setSignedDataFileName)
public:
    explicit DecryptVerifyOperationWidget(QWidget *parent = nullptr);
    ~DecryptVerifyOperationWidget() override;

    enum Mode {
        VerifyDetachedWithSignature,
        VerifyDetachedWithSignedData,
        DecryptVerifyOpaque,
    };
    void setMode(Mode mode, const std::shared_ptr<ArchiveDefinition> &ad);
    void setMode(Mode mode);
    Mode mode() const;

    void setInputFileName(const QString &name);
    QString inputFileName() const;

    void setSignedDataFileName(const QString &name);
    QString signedDataFileName() const;

    void setArchiveDefinitions(const std::vector<std::shared_ptr<ArchiveDefinition>> &ads);
    std::shared_ptr<ArchiveDefinition> selectedArchiveDefinition() const;

Q_SIGNALS:
    void changed();

private:
    class Private;
    const std::unique_ptr<Private> d;
    Q_PRIVATE_SLOT(d, void enableDisableWidgets())
};

}
}
}
