/*
    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2022 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/
#pragma once

#include <QLabel>
#include <QPointer>

namespace Kleo
{

namespace _detail
{
class LabelledWidgetBase
{
protected:
    LabelledWidgetBase() = default;

    QWidget *widget() const;

public:
    QLabel *label() const;

    void setWidgets(QWidget *widget, QLabel *label);

    void setEnabled(bool enabled);

private:
    QPointer<QLabel> mLabel;
    QPointer<QWidget> mWidget;
};
}

/**
 * LabelledWidget is a small value-like class for simplifying the management
 * of a QWidget with associated QLabel.
 */
template<class Widget>
class LabelledWidget : public _detail::LabelledWidgetBase
{
public:
    LabelledWidget()
        : _detail::LabelledWidgetBase{}
    {
    }

    void createWidgets(QWidget *parent)
    {
        setWidgets(new Widget{parent}, new QLabel{parent});
    }

    Widget *widget() const
    {
        return dynamic_cast<Widget *>(_detail::LabelledWidgetBase::widget());
    }
};

}
