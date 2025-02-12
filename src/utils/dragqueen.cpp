/*
    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2007 Klarälvdalens Datakonsult AB

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include <config-kleopatra.h>

#include "dragqueen.h"

#include <QApplication>
#include <QDrag>
#include <QMouseEvent>
#include <QStringList>
#include <QStyle>
#include <QUrl>
#include <QVariant>

#include <algorithm>

using namespace Kleo;

namespace
{
class MimeDataProxy : public QMimeData
{
    Q_OBJECT
public:
    explicit MimeDataProxy(QMimeData *source)
        : QMimeData()
        , m_source(source)
    {
    }

    QStringList formats() const override
    {
        if (m_source) {
            return m_source->formats();
        } else {
            return QStringList();
        }
    }

    bool hasFormat(const QString &format) const override
    {
        return m_source && m_source->hasFormat(format);
    }

protected:
    QVariant retrieveData(const QString &format, QMetaType type) const override
    {
        if (!m_source) {
            return QVariant();
        }
        // Doesn't work, is protected:
        // return m_source->retrieveData( format, type );
        switch (type.id()) {
        case QMetaType::QString:
            if (format == QLatin1StringView("text/plain")) {
                return m_source->text();
            }
            if (format == QLatin1StringView("text/html")) {
                return m_source->html();
            }
            break;
        case QMetaType::QColor:
            if (format == QLatin1StringView("application/x-color")) {
                return m_source->colorData();
            }
            break;
        case QMetaType::QImage:
            if (format == QLatin1StringView("application/x-qt-image")) {
                return m_source->imageData();
            }
            break;
        case QMetaType::QVariantList:
        case QMetaType::QUrl:
            if (format == QLatin1StringView("text/uri-list")) {
                const QList<QUrl> urls = m_source->urls();
                if (urls.size() == 1) {
                    return urls.front();
                }
                QList<QVariant> result;
                std::copy(urls.begin(), urls.end(), std::back_inserter(result));
                return result;
            }
            break;
        default:
            break;
        }

        QVariant v = m_source->data(format);
        v.convert(type);
        return v;
    }

private:
    QPointer<QMimeData> m_source;
};
}

DragQueen::DragQueen(QWidget *p, Qt::WindowFlags f)
    : QLabel(p, f)
    , m_data()
    , m_dragStartPosition()
{
}

DragQueen::DragQueen(const QString &t, QWidget *p, Qt::WindowFlags f)
    : QLabel(t, p, f)
    , m_data()
    , m_dragStartPosition()
{
}

DragQueen::~DragQueen()
{
    delete m_data;
}

void DragQueen::setUrl(const QString &url)
{
    auto data = new QMimeData;
    QList<QUrl> urls;
    urls.push_back(QUrl(url));
    data->setUrls(urls);
    setMimeData(data);
}

QString DragQueen::url() const
{
    if (!m_data || !m_data->hasUrls()) {
        return QString();
    }
    const QList<QUrl> urls = m_data->urls();
    if (urls.empty()) {
        return QString();
    }
    return urls.front().toString();
}

void DragQueen::setMimeData(QMimeData *data)
{
    if (data == m_data) {
        return;
    }
    delete m_data;
    m_data = data;
}

QMimeData *DragQueen::mimeData() const
{
    return m_data;
}

void DragQueen::mousePressEvent(QMouseEvent *e)
{
#ifndef QT_NO_DRAGANDDROP
    if (m_data && e->button() == Qt::LeftButton) {
        m_dragStartPosition = e->pos();
    }
#endif
    QLabel::mousePressEvent(e);
}

static QPoint calculate_hot_spot(const QPoint &mouse, const QSize &pix, const QLabel *label)
{
    const Qt::Alignment align = label->alignment();
    const int margin = label->margin();
    const QRect cr = label->contentsRect().adjusted(margin, margin, -margin, -margin);
    const QRect rect = QStyle::alignedRect(QApplication::layoutDirection(), align, pix, cr);
    return mouse - rect.topLeft();
}

void DragQueen::mouseMoveEvent(QMouseEvent *e)
{
#ifndef QT_NO_DRAGANDDROP
    if (m_data //
        && (e->buttons() & Qt::LeftButton) //
        && (m_dragStartPosition - e->pos()).manhattanLength() > QApplication::startDragDistance()) {
        auto drag = new QDrag(this);
        const QPixmap pix = pixmap();
        if (!pix.isNull()) {
            drag->setPixmap(pix);
            drag->setHotSpot(calculate_hot_spot(e->pos(), pix.size(), this));
        }
        drag->setMimeData(new MimeDataProxy(m_data));
        drag->exec();
    } else {
#endif
        QLabel::mouseMoveEvent(e);
#ifndef QT_NO_DRAGANDDROP
    }
#endif
}

#include "dragqueen.moc"

#include "moc_dragqueen.cpp"
