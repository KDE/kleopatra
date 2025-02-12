/*
    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2007 Klarälvdalens Datakonsult AB

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#pragma once

#include <QLabel>
#include <QMimeData>
#include <QPoint>
#include <QPointer>

namespace Kleo
{

class DragQueen : public QLabel
{
    Q_OBJECT
    Q_PROPERTY(QString url READ url WRITE setUrl)
public:
    explicit DragQueen(QWidget *widget = nullptr, Qt::WindowFlags f = {});
    explicit DragQueen(const QString &text, QWidget *widget = nullptr, Qt::WindowFlags f = {});
    ~DragQueen() override;

    void setUrl(const QString &url);
    QString url() const;

    void setMimeData(QMimeData *md);
    QMimeData *mimeData() const;

protected:
    void mousePressEvent(QMouseEvent *) override;
    void mouseMoveEvent(QMouseEvent *) override;

private:
    QPointer<QMimeData> m_data;
    QPoint m_dragStartPosition;
    QString m_dataFormat;
};

}
