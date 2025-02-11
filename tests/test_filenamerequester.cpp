/* -*- mode: c++; c-basic-offset:4 -*-
    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2007 Klarälvdalens Datakonsult AB

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include <config-kleopatra.h>

#include "../utils/filenamerequester.h"

#include <QApplication>

int main(int argc, char *argv[])
{
    QApplication app(argc, argv);

    Kleo::FileNameRequester requester;
    requester.show();

    return app.exec();
}
