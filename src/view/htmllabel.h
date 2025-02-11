/*
    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2021, 2022 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#pragma once

#include <interfaces/anchorprovider.h>

#include <QLabel>

#include <memory>

namespace Kleo
{

class HtmlLabel : public QLabel, public AnchorProvider
{
    Q_OBJECT
public:
    explicit HtmlLabel(QWidget *parent = nullptr);
    explicit HtmlLabel(const QString &html, QWidget *parent = nullptr);
    ~HtmlLabel() override;

    void setHtml(const QString &html);

    void setLinkColor(const QColor &color);

    // AnchorProvider
    int numberOfAnchors() const override;
    QString anchorText(int index) const override;
    QString anchorHref(int index) const override;
    void activateAnchor(int index) override;
    int selectedAnchor() const override;

protected:
    bool focusNextPrevChild(bool next) override;

private:
    using QLabel::setText;

private:
    class Private;
    std::unique_ptr<Private> d;
};

}
