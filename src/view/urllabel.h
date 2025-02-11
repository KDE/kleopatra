/*
    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2021, 2022 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#pragma once

#include "htmllabel.h"

#include <memory>

namespace Kleo
{

class UrlLabel : public HtmlLabel
{
    Q_OBJECT
public:
    explicit UrlLabel(QWidget *parent = nullptr);
    ~UrlLabel() override;

    void setUrl(const QUrl &url, const QString &text = {});

protected:
    void focusInEvent(QFocusEvent *event) override;

private:
    using HtmlLabel::setHtml;
};

}
