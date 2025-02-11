/*
    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2017 Bundesamt für Sicherheit in der Informationstechnik
    SPDX-FileContributor: Intevation GmbH

    SPDX-License-Identifier: GPL-2.0-or-later
*/
#pragma once

#include <interfaces/focusfirstchild.h>

#include <QWidget>

#include <memory>

namespace Kleo
{
/* Helper Widget that can be shown if a user has no keys */
class WelcomeWidget : public QWidget, public FocusFirstChild
{
    Q_OBJECT
public:
    explicit WelcomeWidget(QWidget *parent = nullptr);

    void focusFirstChild(Qt::FocusReason reason = Qt::OtherFocusReason) override;

private:
    class Private;
    std::shared_ptr<Private> d;
};
} // namespace Kleo
