/* -*- mode: c++; c-basic-offset:4 -*-
    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2010 Klarälvdalens Datakonsult AB

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#pragma once

#include "assuancommand.h"
#include <QObject>

#include <memory>

namespace Kleo
{

class CreateChecksumsCommand : public QObject, public AssuanCommandMixin<CreateChecksumsCommand>
{
    Q_OBJECT
public:
    CreateChecksumsCommand();
    ~CreateChecksumsCommand() override;

    static const char *staticName()
    {
        return "CHECKSUM_CREATE_FILES";
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
