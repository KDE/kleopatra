/*  overlaywidget.h

    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2016 Bundesamt für Sicherheit in der Informationstechnik
    SPDX-FileCopyrightText: 2024 g10 Code GmbH
    SPDX-FileContributor: Intevation GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/
#pragma once

#include <QPointer>
#include <QWidget>

namespace Kleo
{
/**
 * @internal
 * Widget to show a widget as overlay on top of another widget.
 */
class OverlayWidget : public QWidget
{
    Q_OBJECT
public:
    /**
     * Create an overlay widget for @p baseWidget.
     * @p baseWidget must not be @c nullptr.
     * @p parent must not be equal to @p baseWidget
     */
    explicit OverlayWidget(QWidget *baseWidget, QWidget *parent = nullptr);
    ~OverlayWidget() override;

    void setOverlay(QWidget *widget);
    QWidget *overlay() const;

public Q_SLOTS:
    void showOverlay();
    void hideOverlay();

protected:
    bool eventFilter(QObject *object, QEvent *event) override;

private:
    void reposition();

private:
    bool shown = false;
    QWidget *mBaseWidget = nullptr;
    QPointer<QWidget> mOldFocusWidget;
    QPointer<QWidget> mOverlay;
};

} // namespace Kleo
