/*
    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2008 Klarälvdalens Datakonsult AB

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#pragma once

#include <QStringList>
#include <QWidget>

#include <memory>

class QString;

namespace Kleo
{
namespace NewCertificateUi
{

class ListWidget : public QWidget
{
    Q_OBJECT
    Q_PROPERTY(QStringList items READ items WRITE setItems USER true NOTIFY itemsChanged)
    Q_PROPERTY(QRegularExpression regExpFilter READ regExpFilter WRITE setRegExpFilter)
    Q_PROPERTY(QString defaultValue READ defaultValue WRITE setDefaultValue)
public:
    explicit ListWidget(QWidget *parent = nullptr);
    ~ListWidget() override;

    void setDefaultValue(const QString &defaultValue);
    QString defaultValue() const;

    void setRegExpFilter(const QRegularExpression &rx);
    QRegularExpression regExpFilter() const;

    QStringList items() const;

public Q_SLOTS:
    void setItems(const QStringList &items);

Q_SIGNALS:
    void itemsChanged();

private:
    class Private;
    const std::unique_ptr<Private> d;
    Q_PRIVATE_SLOT(d, void slotAdd())
    Q_PRIVATE_SLOT(d, void slotRemove())
    Q_PRIVATE_SLOT(d, void slotUp())
    Q_PRIVATE_SLOT(d, void slotDown())
    Q_PRIVATE_SLOT(d, void slotSelectionChanged())
};

}
}
