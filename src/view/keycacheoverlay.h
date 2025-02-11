/*
    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2016 Bundesamt für Sicherheit in der Informationstechnik
    SPDX-FileContributor: Intevation GmbH

    SPDX-License-Identifier: GPL-2.0-or-later
*/
#pragma once

#include <QTimer>
#include <QWidget>

namespace Kleo
{

/**
 * @internal
 * Overlay widget to block KeyCache-dependent widgets if the Keycache
 * is not initialized.
 */
class KeyCacheOverlay : public QWidget
{
    Q_OBJECT
public:
    /**
     * Create an overlay widget for @p baseWidget.
     * @p baseWidget must not be null.
     * @p parent must not be equal to @p baseWidget
     */
    explicit KeyCacheOverlay(QWidget *baseWidget, QWidget *parent = nullptr);

protected:
    bool eventFilter(QObject *object, QEvent *event) override;

private:
    void reposition();

private Q_SLOTS:
    /** Hides the overlay and triggers deletion. */
    void hideOverlay();

private:
    QWidget *mBaseWidget;
    QTimer mTimer;
};

} // namespace Kleo
