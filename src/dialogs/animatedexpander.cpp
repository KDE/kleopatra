/*

    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2019, 2021 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include "dialogs/animatedexpander.h"

#include <QPropertyAnimation>

void AnimatedExpander::setContentLayout(QLayout *contentLayout)
{
    delete contentArea.layout();
    contentArea.setLayout(contentLayout);
}

bool AnimatedExpander::isExpanded() const
{
    return toggleButton.isChecked();
}

void AnimatedExpander::setExpanded(bool expanded)
{
    toggleButton.setChecked(expanded);
}

AnimatedExpander::AnimatedExpander(const QString &title, const QString &accessibleTitle, QWidget *parent)
    : QWidget{parent}
{
#ifdef Q_OS_WIN
    // draw dotted focus frame if button has focus; otherwise, draw invisible frame using background color
    toggleButton.setStyleSheet(
        QStringLiteral("QToolButton { border: 1px solid palette(window); }"
                       "QToolButton:focus { border: 1px dotted palette(window-text); }"));
#else
    // this works with Breeze style because Breeze draws the focus frame when drawing CE_ToolButtonLabel
    // while the Windows styles (and Qt's common base style) draw the focus frame before drawing CE_ToolButtonLabel
    toggleButton.setStyleSheet(QStringLiteral("QToolButton { border: none; }"));
#endif
    toggleButton.setToolButtonStyle(Qt::ToolButtonTextBesideIcon);
    toggleButton.setArrowType(Qt::ArrowType::RightArrow);
    toggleButton.setText(title);
    if (!accessibleTitle.isEmpty()) {
        toggleButton.setAccessibleName(accessibleTitle);
    }
    toggleButton.setCheckable(true);
    toggleButton.setChecked(false);

    headerLine.setFrameShape(QFrame::HLine);
    headerLine.setFrameShadow(QFrame::Sunken);
    headerLine.setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Maximum);

    contentArea.setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);

    // start out collapsed
    contentArea.setMaximumHeight(0);
    contentArea.setMinimumHeight(0);
    contentArea.setVisible(false);

    // let the entire widget grow and shrink with its content
    toggleAnimation.addAnimation(new QPropertyAnimation(this, "minimumHeight"));
    toggleAnimation.addAnimation(new QPropertyAnimation(this, "maximumHeight"));
    toggleAnimation.addAnimation(new QPropertyAnimation(&contentArea, "maximumHeight"));

    mainLayout.setVerticalSpacing(0);
    mainLayout.setContentsMargins(0, 0, 0, 0);
    int row = 0;
    mainLayout.addWidget(&toggleButton, row, 0, 1, 1, Qt::AlignLeft);
    mainLayout.addWidget(&headerLine, row++, 2, 1, 1);
    mainLayout.addWidget(&contentArea, row, 0, 1, 3);
    setLayout(&mainLayout);
    connect(&toggleButton, &QToolButton::toggled, this, [this](const bool checked) {
        if (checked) {
            Q_EMIT startExpanding();
            // make the content visible when expanding starts
            contentArea.setVisible(true);
        }
        // use instant animation if widget isn't visible (e.g. before widget is shown)
        const int duration = isVisible() ? animationDuration : 0;
        // update the size of the content area
        const auto collapsedHeight = sizeHint().height() - contentArea.maximumHeight();
        const auto contentHeight = contentArea.layout()->sizeHint().height();
        for (int i = 0; i < toggleAnimation.animationCount() - 1; ++i) {
            auto expanderAnimation = static_cast<QPropertyAnimation *>(toggleAnimation.animationAt(i));
            expanderAnimation->setDuration(duration);
            expanderAnimation->setStartValue(collapsedHeight);
            expanderAnimation->setEndValue(collapsedHeight + contentHeight);
        }
        auto contentAnimation = static_cast<QPropertyAnimation *>(toggleAnimation.animationAt(toggleAnimation.animationCount() - 1));
        contentAnimation->setDuration(duration);
        contentAnimation->setStartValue(0);
        contentAnimation->setEndValue(contentHeight);
        toggleButton.setArrowType(checked ? Qt::ArrowType::DownArrow : Qt::ArrowType::RightArrow);
        toggleAnimation.setDirection(checked ? QAbstractAnimation::Forward : QAbstractAnimation::Backward);
        toggleAnimation.start();
    });
    connect(&toggleAnimation, &QAbstractAnimation::finished, this, [this]() {
        // hide the content area when it is fully collapsed
        if (!toggleButton.isChecked()) {
            contentArea.setVisible(false);
        }
    });
}

int AnimatedExpander::contentHeight() const
{
    return contentArea.layout()->sizeHint().height();
}

int AnimatedExpander::contentWidth() const
{
    return contentArea.layout()->sizeHint().width();
}
