/*

    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2019, 2021 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#pragma once

#include <QFrame>
#include <QGridLayout>
#include <QParallelAnimationGroup>
#include <QToolButton>
#include <QWidget>

// based on code from StackOverflow
class AnimatedExpander : public QWidget
{
    Q_OBJECT
public:
    explicit AnimatedExpander(const QString &title, const QString &accessibleTitle = {}, QWidget *parent = nullptr);

    void setContentLayout(QLayout *contentLayout);

    bool isExpanded() const;
    void setExpanded(bool expanded);

    int contentHeight() const;
    int contentWidth() const;

Q_SIGNALS:
    void startExpanding();

private:
    static const int animationDuration = 300;

    QGridLayout mainLayout;
    QToolButton toggleButton;
    QFrame headerLine;
    QParallelAnimationGroup toggleAnimation;
    QWidget contentArea;
};
