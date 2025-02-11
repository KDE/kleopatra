/*
    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2021, 2022 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include "accessiblewidgetfactory.h"

#include "accessiblerichtextlabel_p.h"
#include "accessiblevaluelabel_p.h"

#include "utils/accessibility.h"
#include "view/htmllabel.h"
#include "view/urllabel.h"

QAccessibleInterface *Kleo::accessibleWidgetFactory(const QString &classname, QObject *object)
{
    QAccessibleInterface *iface = nullptr;
    if (!object || !object->isWidgetType())
        return iface;

    QWidget *widget = static_cast<QWidget *>(object);

    if (classname == QString::fromLatin1(Kleo::HtmlLabel::staticMetaObject.className())
        || classname == QString::fromLatin1(Kleo::UrlLabel::staticMetaObject.className())) {
        iface = new AccessibleRichTextLabel{widget};
    } else if (classname == QLatin1StringView("QLabel") && Kleo::representAsAccessibleValueWidget(widget)) {
        iface = new AccessibleValueLabel{widget};
    }

    return iface;
}
