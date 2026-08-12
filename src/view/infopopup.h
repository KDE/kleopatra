/*
    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2026 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/
#pragma once

#include <KMessageWidget>

namespace Kleo
{

class InfoPopup : public KMessageWidget
{
    Q_OBJECT
public:
    static void showText(const QPoint &pos, const QString &text, QWidget *w = nullptr);

    explicit InfoPopup(QWidget *parent = nullptr);
    explicit InfoPopup(const QString &text, QWidget *parent = nullptr);
    ~InfoPopup() override;

protected:
    void showEvent(QShowEvent *event) override;

private:
    bool mIsFirstShowEvent = true;
};

}
