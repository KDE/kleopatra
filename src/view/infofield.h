/*  view/infofield.h

    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2022 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/
#pragma once

#include <QString>

class QAction;
class QHBoxLayout;
class QIcon;
class QLabel;
class QLayout;
class QPushButton;
class QWidget;

namespace Kleo
{

class InfoField
{
public:
    InfoField(const QString &label, QWidget *parent);

    /** Returns the label which displays the label text. Add it to the UI. */
    QLabel *label() const;
    /**
     * Returns the layout containing the value label and the optional action button.
     * Add it to the UI.
     */
    QLayout *layout() const;

    /**
     * Returns the label which displays the value.
     * Don't add this label to the UI. Instead add layout() to the UI.
     * Use this accessor if you need to change some properties of the value
     * label, e.g. the text interaction flags.
     */
    QLabel *valueLabel() const;

    void setValue(const QString &value, const QString &accessibleValue = {});
    QString value() const;

    void setIcon(const QIcon &icon);
    void setAction(const QAction *action);
    void setToolTip(const QString &toolTip);
    void setVisible(bool visible);

private:
    void onActionChanged();

    QLabel *mLabel = nullptr;
    QHBoxLayout *mLayout = nullptr;
    QLabel *mIcon = nullptr;
    QLabel *mValue = nullptr;
    QPushButton *mButton = nullptr;
    const QAction *mAction = nullptr;
};

}
