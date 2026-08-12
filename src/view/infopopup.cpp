/*
    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2026 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include "infopopup.h"

#include <QGuiApplication>
#include <QScreen>
#include <QTimer>
#include <QToolButton>

#include <kleopatra_debug.h>

using namespace Kleo;
using namespace std::literals::chrono_literals;

InfoPopup::InfoPopup(QWidget *parent)
    : InfoPopup{QString{}, parent}
{
}

InfoPopup::InfoPopup(const QString &text, QWidget *parent)
    : KMessageWidget{text, parent}
{
    setWindowFlags(Qt::Popup);
    if (auto closeButton = findChild<QToolButton *>()) {
        if (auto closeAction = closeButton->defaultAction()) {
            // handle the Close action ourselves to get rid of the hide animation
            QObject::disconnect(closeAction, &QAction::triggered, this, &KMessageWidget::animatedHide);
            QObject::connect(closeAction, &QAction::triggered, this, &QWidget::close);
        }
    } else {
        qDebug(KLEOPATRA_LOG) << __func__ << "Close button not found";
    }
}

InfoPopup::~InfoPopup()
{
}

void InfoPopup::showEvent(QShowEvent *event)
{
    if (mIsFirstShowEvent) {
        mIsFirstShowEvent = false;

        // ensure that the popup is fully visible on the screen
        const QPoint globalPos = mapToGlobal(QPoint{0, 0});
        QScreen *screen = QGuiApplication::screenAt(globalPos);
        if (!screen) {
            screen = QGuiApplication::primaryScreen();
        }
        const QRect screenRect = screen->geometry();
        int x = globalPos.x();
        if (x + width() > screenRect.right()) {
            x = qMax(screenRect.right() - width(), screenRect.x());
        }
        int y = globalPos.y();
        if (y + height() > screenRect.bottom()) {
            y = qMax(screenRect.bottom() - height(), screenRect.y());
        }

        move(x, y);
    }

    KMessageWidget::showEvent(event);
}

void InfoPopup::showText(const QPoint &pos, const QString &text, QWidget *w)
{
    auto popup = new InfoPopup{w};
    popup->setAttribute(Qt::WA_DeleteOnClose, true);
    // use word wrap to prevent very wide popup
    popup->setWordWrap(true);
    popup->setText(text);
    popup->move(pos);
    popup->show();
    // delay moving focus to the info popup to avoid wrong order of accessible notifications;
    // if setFocus() is called directly then Narrator and NVDA on Windows speak "Note" (the
    // accessible name of the InfoPopup/KMessageWidget) instead of the text because Windows appears to
    // create a synthetic focus event for the popup which overrides Qt's focus event for the text
    QTimer::singleShot(100ms, popup, qOverload<>(&InfoPopup::setFocus));
}

#include "moc_infopopup.cpp"
