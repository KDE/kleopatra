/*
    appearanceconfigwidget.h

    This file is part of kleopatra, the KDE key manager
    SPDX-FileCopyrightText: 2002, 2004, 2008 Klarälvdalens Datakonsult AB
    SPDX-FileCopyrightText: 2002, 2003 Marc Mutz <mutz@kde.org>

    SPDX-License-Identifier: GPL-2.0-or-later
 */

#pragma once

#include <QWidget>

#include <memory>

namespace Kleo
{
namespace Config
{

class AppearanceConfigWidget : public QWidget
{
    Q_OBJECT
public:
    explicit AppearanceConfigWidget(QWidget *parent = nullptr, Qt::WindowFlags f = {});
    ~AppearanceConfigWidget() override;

public Q_SLOTS:
    void load();
    void save();
    void defaults();

Q_SIGNALS:
    void changed();

private:
    class Private;
    const std::unique_ptr<Private> d;
    Q_PRIVATE_SLOT(d, void slotIconClicked())
#ifndef QT_NO_COLORDIALOG
    Q_PRIVATE_SLOT(d, void slotForegroundClicked())
    Q_PRIVATE_SLOT(d, void slotBackgroundClicked())
#endif
#ifndef QT_NO_FONTDIALOG
    Q_PRIVATE_SLOT(d, void slotFontClicked())
#endif
    Q_PRIVATE_SLOT(d, void slotSelectionChanged())
    Q_PRIVATE_SLOT(d, void slotDefaultClicked())
    Q_PRIVATE_SLOT(d, void slotItalicToggled(bool))
    Q_PRIVATE_SLOT(d, void slotBoldToggled(bool))
    Q_PRIVATE_SLOT(d, void slotStrikeOutToggled(bool))
    Q_PRIVATE_SLOT(d, void slotTooltipValidityChanged(bool))
    Q_PRIVATE_SLOT(d, void slotTooltipDetailsChanged(bool))
    Q_PRIVATE_SLOT(d, void slotTooltipOwnerChanged(bool))
};

}
}
