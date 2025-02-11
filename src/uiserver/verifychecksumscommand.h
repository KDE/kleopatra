/* -*- mode: c++; c-basic-offset:4 -*-
    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2010 Klarälvdalens Datakonsult AB

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#pragma once

#include "assuancommand.h"

#ifndef QT_NO_DIRMODEL

#include <QObject>

namespace Kleo
{

class VerifyChecksumsCommand : public QObject, public AssuanCommandMixin<VerifyChecksumsCommand>
{
    Q_OBJECT
public:
    VerifyChecksumsCommand();
    ~VerifyChecksumsCommand() override;

    static const char *staticName()
    {
        return "CHECKSUM_VERIFY_FILES";
    }

private:
    int doStart() override;
    void doCanceled() override;

#ifdef Q_MOC_RUN
private Q_SLOTS:
    void done();
    void done(int, QString);
#endif

private:
    class Private;
    const std::unique_ptr<Private> d;
};

}

#endif // QT_NO_DIRMODEL
