/*
    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2016 Bundesamt für Sicherheit in der Informationstechnik
    SPDX-FileCopyrightText: 2024 g10 Code GmbH
    SPDX-FileContributor: Intevation GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include "textoverlay.h"

#include <QHBoxLayout>
#include <QLabel>
#include <QVBoxLayout>

using namespace Kleo;

TextOverlay::TextOverlay(QWidget *baseWidget, QWidget *parent)
    : OverlayWidget{baseWidget, parent}
{
    auto widget = new QWidget{this};
    auto vbox = new QVBoxLayout{widget};

    auto hbox = new QHBoxLayout;
    hbox->addStretch(1);
    auto label = new QLabel{this};
    mLabelHelper.addLabel(label);
    hbox->addWidget(label);
    hbox->addStretch(1);

    vbox->addStretch(1);
    vbox->addLayout(hbox);
    vbox->addStretch(1);

    setOverlay(widget);
    setFocusProxy(label);
    setFocusPolicy(label->focusPolicy());
}

TextOverlay::~TextOverlay() = default;

void TextOverlay::setText(const QString &text)
{
    if (auto label = overlay()->findChild<QLabel *>()) {
        label->setText(text);
    }
}

QString TextOverlay::text() const
{
    if (auto label = overlay()->findChild<const QLabel *>()) {
        return label->text();
    }
    return {};
}

#include "moc_textoverlay.cpp"
