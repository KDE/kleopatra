/*
    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2018 Intevation GmbH

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#pragma once

#include <interfaces/focusfirstchild.h>

#include <QWidget>

#include <memory>

namespace Kleo
{
/** The padwidget provides a general I/O area inside of kleopatra
 * and can be used as an alternative view to the tabwidget. */
class PadWidget : public QWidget, public FocusFirstChild
{
    Q_OBJECT
public:
    explicit PadWidget(QWidget *parent = nullptr);

    void focusFirstChild(Qt::FocusReason reason = Qt::OtherFocusReason) override;

private:
    class Private;
    std::shared_ptr<Private> d;
};
} // namespace Kleo
