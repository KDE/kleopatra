/*
    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2024 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/
#pragma once

#include "overlaywidget.h"

#include <utils/accessibility.h>

namespace Kleo
{

/**
 * @internal
 * Widget to overlay another widget with a text.
 */
class TextOverlay : public OverlayWidget
{
    Q_OBJECT
public:
    /**
     * Create an overlay widget for @p baseWidget.
     * @p baseWidget must not be @c nullptr.
     * @p parent must not be equal to @p baseWidget
     */
    explicit TextOverlay(QWidget *baseWidget, QWidget *parent = nullptr);
    ~TextOverlay() override;

    void setText(const QString &text);
    QString text() const;

private:
    LabelHelper mLabelHelper;
};

} // namespace Kleo
